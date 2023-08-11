package msg

// helpers / fixes to automatically generated code
// probably the real fix would be to fork the generator

var AttrCodeValue = _AttrCodeNameToValueMap
var AttrCodeName = map[AttrCode]string{}

var ExcomTypeValue = _ExcomTypeNameToValueMap
var ExcomTypeName = map[ExcomType]string{}

func init() {
	for _, v := range AttrCodeValues() {
		AttrCodeName[v] = v.String()
	}

	for _, v := range ExcomTypeValues() {
		ExcomTypeName[v] = v.String()
	}
}
