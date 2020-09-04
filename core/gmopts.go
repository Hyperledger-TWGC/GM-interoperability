package core


const (
	TJFOC_GM = "tjfoc-gm"

	CCS_GM = "ccs-gm"

	PKU_GM="pku-gm"
)


type SM4Type interface{}

var gmopts = 1

func NewGM() string{

	switch gmopts {
	case 1:
		return TJFOC_GM
	case 2:
		return CCS_GM
	case 3:
		return PKU_GM
	default:
		return "" //your gm
	}

}



