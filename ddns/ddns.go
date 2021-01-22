package ddns

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"github.com/google/go-querystring/query"
	"github.com/google/uuid"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"time"
)

var replaceMap = map[string]string{
	"+":   "%20",
	"*":   "%2A",
	"%7E": "~",
}

type BaseParameter struct {
	Format           string
	Version          string
	AccessKeyId      string
	Timestamp        string
	Action           string
	SignatureMethod  string
	SignatureNonce   string
	SignatureVersion string
}

func NewBaseParameter(ak string, action string) BaseParameter {
	return BaseParameter{
		Format:           "JSON",
		Version:          "2015-01-09",
		AccessKeyId:      ak,
		Timestamp:        time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		Action:           action,
		SignatureMethod:  "HMAC-SHA1",
		SignatureNonce:   strings.ReplaceAll(uuid.New().String(), "-", ""),
		SignatureVersion: "1.0",
	}
}

type UpdateDomainParameter struct {
	BaseParameter
	Type     string
	RR       string
	RecordId string
	Value    string
	Line     string
	TTL      int
}

func NewUpdateDomainParameter(ak string, recordId string, recordType string, hostRecord string, recordValue string, line string, ttl int) UpdateDomainParameter {
	return UpdateDomainParameter{
		BaseParameter: NewBaseParameter(ak, "UpdateDomainRecord"),
		Type:          recordType,
		RR:            hostRecord,
		RecordId:      recordId,
		Value:         recordValue,
		Line:          line,
		TTL:           ttl,
	}
}

type DescribeDomainParameter struct {
	BaseParameter
	Type       string
	DomainName string
	RRKeyWord  string
}

func NewDescribeDomainParameter(ak string, recordType string, domain string, hostRecord string) DescribeDomainParameter {
	return DescribeDomainParameter{
		BaseParameter: NewBaseParameter(ak, "DescribeDomainRecords"),
		Type:          recordType,
		DomainName:    domain,
		RRKeyWord:     hostRecord,
	}
}

type AddDomainParameter struct {
	BaseParameter
	Type       string
	DomainName string
	RR         string
	Value      string
	Line       string
	TTL        int
}

func NewAddDomainParameter(ak string, recordType string, domain string, hostRecord string, value string, line string, ttl int) AddDomainParameter {
	return AddDomainParameter{
		BaseParameter: NewBaseParameter(ak, "AddDomainRecord"),
		Type:          recordType,
		DomainName:    domain,
		RR:            hostRecord,
		Value:         value,
		Line:          line,
		TTL:           ttl,
	}
}

func Sign(obj interface{}, sk string) string {
	t := reflect.TypeOf(obj)
	v := reflect.ValueOf(obj)

	var data = make(map[string]interface{})
	for i := 0; i < t.NumField(); i++ {
		if v.Field(i).Type().Kind() == reflect.Struct {
			structField := v.Field(i).Type()
			for j := 0; j < structField.NumField(); j++ {
				data[structField.Field(j).Name] = v.Field(i).Field(j).Interface()
			}
		} else {
			data[t.Field(i).Name] = v.Field(i).Interface()
		}
	}
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var q = url.Values{}
	for _, k := range keys {
		q.Add(k, fmt.Sprintf("%v", data[k]))
	}
	string2Sign := "GET&%2F&" + url.QueryEscape(q.Encode())
	for k, v := range replaceMap {
		strings.ReplaceAll(string2Sign, k, v)
	}
	mac := hmac.New(sha1.New, []byte(sk+"&"))
	mac.Write([]byte(string2Sign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func BuildURL(parameter interface{}, sk string) string {
	signature := Sign(parameter, sk)
	dnsUrl, err := url.Parse("https://alidns.aliyuncs.com/")
	if err != nil {
		return ""
	}
	v, err := query.Values(parameter)
	if err != nil {
		return ""
	}
	v.Set("Signature", signature)
	dnsUrl.RawQuery = v.Encode()
	return dnsUrl.String()
}

func SplitDomain(domain string) (record string, topDomain string) {
	i1 := strings.LastIndex(domain, ".")
	i2 := strings.LastIndex(domain[:i1], ".")
	record = domain[:i2]
	topDomain = domain[(i2 + 1):]
	return
}

type DomainRecord struct {
	RR         string
	Line       string
	Status     string
	Locked     bool
	Type       string
	DomainName string
	Value      string
	RecordId   string
	TTL        int
	Weight     int
}
