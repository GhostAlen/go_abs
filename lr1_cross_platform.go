package main

import (
	"fmt"

	"io"
	"os"

	"github.com/fogleman/gg"
	geojson "github.com/paulmach/go.geojson"
)

func main() {
	
	file, err := os.Open("chto-to.json")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer file.Close()
	data := make([]byte, 64)

	geomData := ""
	for {
		n, err := file.Read(data)
		if err == io.EOF { // если конец файла
			break // выходим из цикла
		}
		geomData = geomData + string(data[:n])
	}
	// Feature Collection
	rawFeatureJSON := []byte(geomData)

	fc1, err := geojson.UnmarshalFeatureCollection(rawFeatureJSON)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	dc := gg.NewContext(1000, 1000)
	dc.SetHexColor("fff")
	//here we draw
	dc.Scale(9, 9)
	dc.MoveTo(fc1.Features[0].Geometry.Polygon[0][0][0], fc1.Features[0].Geometry.Polygon[0][0][1])
	for i := 0; i < 5; i++ {

		dc.LineTo(fc1.Features[0].Geometry.Polygon[0][i][0], fc1.Features[0].Geometry.Polygon[0][i][1])

	}
	dc.SetRGB(0, 0, 1)
	dc.InvertY()
	dc.Fill()
	dc.SavePNG("cheburej.png")

}
