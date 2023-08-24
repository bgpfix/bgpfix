package attrs

// helpers / fixes to automatically generated code
// probably the real fix would be to fork the generator

var CodeValue = _CodeNameToValueMap
var CodeName = map[Code]string{}

var ExtcomTypeValue = _ExtcomTypeNameToValueMap
var ExtcomTypeName = map[ExtcomType]string{}

var FlowTypeValue = _FlowTypeNameToValueMap
var FlowTypeName = map[FlowType]string{}

func init() {
	for _, v := range CodeValues() {
		CodeName[v] = v.String()
	}

	for _, v := range ExtcomTypeValues() {
		ExtcomTypeName[v] = v.String()
	}

	for _, v := range FlowTypeValues() {
		FlowTypeName[v] = v.String()
	}
}
