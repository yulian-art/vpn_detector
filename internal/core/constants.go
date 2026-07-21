package core

import "regexp"

var BlockSizes = []int{1300, 1370, 1400, 1448, 1452, 1310, 1344, 1428, 1378}

var StandardTLSPorts = map[int]bool{443: true, 8443: true, 9443: true}

var SpecialPorts = map[int]bool{
	5608: true, 65311: true, 22225: true, 22226: true,
	11581: true, 11582: true, 11681: true, 11000: true,
	3128: true, 8388: true, 22231: true, 51820: true,
	1194: true, 1195: true,
}

var DomainKeywords = []string{
	"nodesni", "kunlun04dns", "sdv2-",
	"gosttwo", "shdowsocks",
	"ahahub", "ahapivot", "hubebay", "hubups", "hubdhl", "jsq456",
	"helloaha", "xinguawl", "footprintdns",
	"wizvpn.net",
	"skylinevpn", "skylinenode",
	"kuaifan.co", "wifiin.cn",
	"securepaidvpn",
	"su89-cdn", "c6gj-static", "x-cdn-static", "zspeed-cdn",
	"zagent",
	"clashverge",
	"cyberghostvpn",
	"shdufysuf",
	"mujica.one", "closedai.cfd", "closedai.date",
	"biliworld.top", "love-live.top",
	"mizulina.top",
	"kbz0pwvxmv", "yg5sjx5kzy",
	"webdrone.club", "zebpay.site",
	"carolinafreigh.fun", "jewelscollecti.icu",
	"vogelsenmeer.xyz", "southwestcoast.pro", "jgwynphotoarts.pro",
}

var RiskTLDs = []string{".icu", ".fun", ".xyz", ".club", ".site", ".top", ".cfd", ".date", ".one", ".pro"}

var ISOCountryCodes = map[string]bool{
	"hk": true, "jp": true, "sg": true, "us": true, "nl": true, "ru": true,
	"lu": true, "gb": true, "tw": true, "kr": true, "de": true, "fr": true,
	"ca": true, "au": true, "in": true, "br": true,
}

var FamousEnterpriseSNI = []string{
	"www.intel.com", "www.tesla.com", "www.ibm.com",
	"www.oracle.com", "www.cisco.com", "aws.amazon.com",
	"www.deloitte.com", "www.pwc.com", "www.sap.com",
	"www.bmw.com", "www.honda.com", "www.americanexpress.com",
	"www.costco.com", "www.emirates.com", "www.mathworks.com",
	"kpmg.com", "www.volvogroup.com", "www.mazda.com",
}

var (
	ChromeJA4Prefix = regexp.MustCompile(`^t13d151[0-9]h`)
	JA4GoPattern    = regexp.MustCompile(`^t13d1011h2_.*`)
	TLS10JA4        = regexp.MustCompile(`^t10d`)
	RegionalNodeRe  = regexp.MustCompile(`(?i)^([a-z]{2})\d+([-.]|$)`)
)
