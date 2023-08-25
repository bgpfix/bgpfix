package caps

// helpers / fixes to automatically generated code
// probably the real fix would be to fork the generator

var CodeValue = _CodeNameToValueMap
var CodeName = map[Code]string{}

func init() {
	for _, v := range CodeValues() {
		CodeName[v] = v.String()
	}
}
