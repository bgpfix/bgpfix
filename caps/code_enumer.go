// Code generated by "enumer -type=Code -trimprefix CAP_"; DO NOT EDIT.

package caps

import (
	"fmt"
	"strings"
)

const (
	_CodeName_0      = "UNSPECIFIEDMPROUTE_REFRESHOUTBOUND_FILTERING"
	_CodeLowerName_0 = "unspecifiedmproute_refreshoutbound_filtering"
	_CodeName_1      = "EXTENDED_NEXTHOPEXTENDED_MESSAGEBGPSECMULTIPLE_LABELSROLE"
	_CodeLowerName_1 = "extended_nexthopextended_messagebgpsecmultiple_labelsrole"
	_CodeName_2      = "GRACEFUL_RESTARTAS4"
	_CodeLowerName_2 = "graceful_restartas4"
	_CodeName_3      = "DYNAMICMULTISESSIONADDPATHENHANCED_ROUTE_REFRESHLLGRROUTING_POLICYFQDNBFDVERSION"
	_CodeLowerName_3 = "dynamicmultisessionaddpathenhanced_route_refreshllgrrouting_policyfqdnbfdversion"
	_CodeName_4      = "PRE_ROUTE_REFRESH"
	_CodeLowerName_4 = "pre_route_refresh"
)

var (
	_CodeIndex_0 = [...]uint8{0, 11, 13, 26, 44}
	_CodeIndex_1 = [...]uint8{0, 16, 32, 38, 53, 57}
	_CodeIndex_2 = [...]uint8{0, 16, 19}
	_CodeIndex_3 = [...]uint8{0, 7, 19, 26, 48, 52, 66, 70, 73, 80}
	_CodeIndex_4 = [...]uint8{0, 17}
)

func (i Code) String() string {
	switch {
	case 0 <= i && i <= 3:
		return _CodeName_0[_CodeIndex_0[i]:_CodeIndex_0[i+1]]
	case 5 <= i && i <= 9:
		i -= 5
		return _CodeName_1[_CodeIndex_1[i]:_CodeIndex_1[i+1]]
	case 64 <= i && i <= 65:
		i -= 64
		return _CodeName_2[_CodeIndex_2[i]:_CodeIndex_2[i+1]]
	case 67 <= i && i <= 75:
		i -= 67
		return _CodeName_3[_CodeIndex_3[i]:_CodeIndex_3[i+1]]
	case i == 128:
		return _CodeName_4
	default:
		return fmt.Sprintf("Code(%d)", i)
	}
}

// An "invalid array index" compiler error signifies that the constant values have changed.
// Re-run the stringer command to generate them again.
func _CodeNoOp() {
	var x [1]struct{}
	_ = x[CAP_UNSPECIFIED-(0)]
	_ = x[CAP_MP-(1)]
	_ = x[CAP_ROUTE_REFRESH-(2)]
	_ = x[CAP_OUTBOUND_FILTERING-(3)]
	_ = x[CAP_EXTENDED_NEXTHOP-(5)]
	_ = x[CAP_EXTENDED_MESSAGE-(6)]
	_ = x[CAP_BGPSEC-(7)]
	_ = x[CAP_MULTIPLE_LABELS-(8)]
	_ = x[CAP_ROLE-(9)]
	_ = x[CAP_GRACEFUL_RESTART-(64)]
	_ = x[CAP_AS4-(65)]
	_ = x[CAP_DYNAMIC-(67)]
	_ = x[CAP_MULTISESSION-(68)]
	_ = x[CAP_ADDPATH-(69)]
	_ = x[CAP_ENHANCED_ROUTE_REFRESH-(70)]
	_ = x[CAP_LLGR-(71)]
	_ = x[CAP_ROUTING_POLICY-(72)]
	_ = x[CAP_FQDN-(73)]
	_ = x[CAP_BFD-(74)]
	_ = x[CAP_VERSION-(75)]
	_ = x[CAP_PRE_ROUTE_REFRESH-(128)]
}

var _CodeValues = []Code{CAP_UNSPECIFIED, CAP_MP, CAP_ROUTE_REFRESH, CAP_OUTBOUND_FILTERING, CAP_EXTENDED_NEXTHOP, CAP_EXTENDED_MESSAGE, CAP_BGPSEC, CAP_MULTIPLE_LABELS, CAP_ROLE, CAP_GRACEFUL_RESTART, CAP_AS4, CAP_DYNAMIC, CAP_MULTISESSION, CAP_ADDPATH, CAP_ENHANCED_ROUTE_REFRESH, CAP_LLGR, CAP_ROUTING_POLICY, CAP_FQDN, CAP_BFD, CAP_VERSION, CAP_PRE_ROUTE_REFRESH}

var _CodeNameToValueMap = map[string]Code{
	_CodeName_0[0:11]:       CAP_UNSPECIFIED,
	_CodeLowerName_0[0:11]:  CAP_UNSPECIFIED,
	_CodeName_0[11:13]:      CAP_MP,
	_CodeLowerName_0[11:13]: CAP_MP,
	_CodeName_0[13:26]:      CAP_ROUTE_REFRESH,
	_CodeLowerName_0[13:26]: CAP_ROUTE_REFRESH,
	_CodeName_0[26:44]:      CAP_OUTBOUND_FILTERING,
	_CodeLowerName_0[26:44]: CAP_OUTBOUND_FILTERING,
	_CodeName_1[0:16]:       CAP_EXTENDED_NEXTHOP,
	_CodeLowerName_1[0:16]:  CAP_EXTENDED_NEXTHOP,
	_CodeName_1[16:32]:      CAP_EXTENDED_MESSAGE,
	_CodeLowerName_1[16:32]: CAP_EXTENDED_MESSAGE,
	_CodeName_1[32:38]:      CAP_BGPSEC,
	_CodeLowerName_1[32:38]: CAP_BGPSEC,
	_CodeName_1[38:53]:      CAP_MULTIPLE_LABELS,
	_CodeLowerName_1[38:53]: CAP_MULTIPLE_LABELS,
	_CodeName_1[53:57]:      CAP_ROLE,
	_CodeLowerName_1[53:57]: CAP_ROLE,
	_CodeName_2[0:16]:       CAP_GRACEFUL_RESTART,
	_CodeLowerName_2[0:16]:  CAP_GRACEFUL_RESTART,
	_CodeName_2[16:19]:      CAP_AS4,
	_CodeLowerName_2[16:19]: CAP_AS4,
	_CodeName_3[0:7]:        CAP_DYNAMIC,
	_CodeLowerName_3[0:7]:   CAP_DYNAMIC,
	_CodeName_3[7:19]:       CAP_MULTISESSION,
	_CodeLowerName_3[7:19]:  CAP_MULTISESSION,
	_CodeName_3[19:26]:      CAP_ADDPATH,
	_CodeLowerName_3[19:26]: CAP_ADDPATH,
	_CodeName_3[26:48]:      CAP_ENHANCED_ROUTE_REFRESH,
	_CodeLowerName_3[26:48]: CAP_ENHANCED_ROUTE_REFRESH,
	_CodeName_3[48:52]:      CAP_LLGR,
	_CodeLowerName_3[48:52]: CAP_LLGR,
	_CodeName_3[52:66]:      CAP_ROUTING_POLICY,
	_CodeLowerName_3[52:66]: CAP_ROUTING_POLICY,
	_CodeName_3[66:70]:      CAP_FQDN,
	_CodeLowerName_3[66:70]: CAP_FQDN,
	_CodeName_3[70:73]:      CAP_BFD,
	_CodeLowerName_3[70:73]: CAP_BFD,
	_CodeName_3[73:80]:      CAP_VERSION,
	_CodeLowerName_3[73:80]: CAP_VERSION,
	_CodeName_4[0:17]:       CAP_PRE_ROUTE_REFRESH,
	_CodeLowerName_4[0:17]:  CAP_PRE_ROUTE_REFRESH,
}

var _CodeNames = []string{
	_CodeName_0[0:11],
	_CodeName_0[11:13],
	_CodeName_0[13:26],
	_CodeName_0[26:44],
	_CodeName_1[0:16],
	_CodeName_1[16:32],
	_CodeName_1[32:38],
	_CodeName_1[38:53],
	_CodeName_1[53:57],
	_CodeName_2[0:16],
	_CodeName_2[16:19],
	_CodeName_3[0:7],
	_CodeName_3[7:19],
	_CodeName_3[19:26],
	_CodeName_3[26:48],
	_CodeName_3[48:52],
	_CodeName_3[52:66],
	_CodeName_3[66:70],
	_CodeName_3[70:73],
	_CodeName_3[73:80],
	_CodeName_4[0:17],
}

// CodeString retrieves an enum value from the enum constants string name.
// Throws an error if the param is not part of the enum.
func CodeString(s string) (Code, error) {
	if val, ok := _CodeNameToValueMap[s]; ok {
		return val, nil
	}

	if val, ok := _CodeNameToValueMap[strings.ToLower(s)]; ok {
		return val, nil
	}
	return 0, fmt.Errorf("%s does not belong to Code values", s)
}

// CodeValues returns all values of the enum
func CodeValues() []Code {
	return _CodeValues
}

// CodeStrings returns a slice of all String values of the enum
func CodeStrings() []string {
	strs := make([]string, len(_CodeNames))
	copy(strs, _CodeNames)
	return strs
}

// IsACode returns "true" if the value is listed in the enum definition. "false" otherwise
func (i Code) IsACode() bool {
	for _, v := range _CodeValues {
		if i == v {
			return true
		}
	}
	return false
}