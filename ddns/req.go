package ddns

import (
	"encoding/json"
	"errors"
	"github.com/mitchellh/mapstructure"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
)

func getInterfaceAddr(ifName string, v6 bool) (*net.TCPAddr, error) {
	ief, err := net.InterfaceByName(ifName)
	if err != nil {
		return nil, err
	}
	addrs, err := ief.Addrs()
	if err != nil {
		return nil, err
	}

	var useIP *net.IPNet
	for _, addr := range addrs {
		addr4 := addr.(*net.IPNet).IP.To4()
		if (v6 && addr4 == nil) || (!v6 && addr4 != nil) {
			useIP = addr.(*net.IPNet)
			break
		}
	}
	if useIP == nil {
		return nil, errors.New("no IP found")
	}
	return &net.TCPAddr{
		IP: useIP.IP,
	}, nil
}

func GetHTTPClient(ifName string, v6 bool) (*http.Client, error) {
	if ifName == "" {
		return &http.Client{}, nil
	}
	addr, err := getInterfaceAddr(ifName, v6)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{LocalAddr: addr}).DialContext,
		},
	}, nil
}

func HTTPGet(u string, ifName string, v6 bool) ([]byte, error) {
	client, err := GetHTTPClient(ifName, v6)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func HTTPGetJSON(u string, ifName string, v6 bool) (map[string]interface{}, error) {
	result, err := HTTPGet(u, ifName, v6)
	if err != nil {
		return nil, err
	}
	jsonResult := make(map[string]interface{})
	err = json.Unmarshal(result, &jsonResult)
	if err != nil {
		return nil, err
	}
	return jsonResult, nil
}

func QueryRecord(parameter DescribeDomainParameter, sk string, ifName string) (*DomainRecord, error) {
	domainUrl := BuildURL(parameter, sk)
	result, err := HTTPGetJSON(domainUrl, ifName, false)
	if err != nil {
		return nil, err
	}
	domainRecords, ok := result["DomainRecords"]
	if !ok {
		return nil, errors.New(result["Message"].(string))
	}
	drList := make([]DomainRecord, 0)
	if dr, ok := domainRecords.(map[string]interface{}); ok {
		if r, ok := dr["Record"]; ok {
			mapstructure.Decode(r, &drList)
		}
	}
	if len(drList) > 0 {
		return &drList[0], nil
	}
	return nil, nil
}

func UpdateRecord(parameter UpdateDomainParameter, sk string, ifName string) error {
	updateUrl := BuildURL(parameter, sk)
	result, err := HTTPGetJSON(updateUrl, ifName, false)
	if err != nil {
		return err
	}
	if msg, ok := result["Message"]; ok {
		return errors.New(msg.(string))
	}
	return nil
}

func AddRecord(parameter AddDomainParameter, sk string, ifName string) error {
	addUrl := BuildURL(parameter, sk)
	result, err := HTTPGetJSON(addUrl, ifName, false)
	if err != nil {
		return err
	}
	if msg, ok := result["Message"]; ok {
		return errors.New(msg.(string))
	}
	return nil
}

func DetectIP(source string, ifName string, v6 bool) (string, error) {
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		result, err := HTTPGet(source, ifName, v6)
		if err != nil {
			return "", err
		}
		return string(result), nil
	}
	addr, err := getInterfaceAddr(source, v6)
	if err != nil {
		return "", err
	}
	return addr.IP.String(), nil
}
