package main

import 
(	
	"fmt"
	"flag"
	"archive/zip"
	"bytes"
	"os"
	"errors"
	"io/ioutil"
	"path/filepath"
	"github.com/fullsailor/pkcs7"
	"crypto/x509"
	"crypto/tls"
    "crypto/sha1"
    "encoding/json"
    "encoding/binary"
)

func main() {
	var mode, hash, cert, pkey, source, destination string
	flag.StringVar(&mode, "i_want", "i", 
		"Modes: z(zip), x(extract) or i(info)")
	flag.StringVar(&hash, "hash", "UNDEF", 
		"Hash")
	flag.StringVar(&cert, "cert", "./my.crt", 
		"Cert")
	flag.StringVar(&pkey, "pkey", "./my.key", 
		"Pkey")
	flag.StringVar(&source, "way", "UNDEF", 
		"Source")
	flag.StringVar(&destination, "d", "./", 
		"Destination")
	flag.Parse()

	switch mode {
	case "zip": 
		fmt.Printf("Processing...\n")
		if source == "UNDEF" {
			fmt.Println("weresde SOURSE!")
			os.Exit(-1)
		}
		err := szip(source, destination, cert, pkey)
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}
		fmt.Printf("packed\n")
		os.Exit(0)
	case "extr":
		fmt.Printf("loading, do not turn your computer off...\n")
		if source == "UNDEF" {
			fmt.Println("weresde SOURSE!")
			os.Exit(-1)
		}
		err := extract(source, destination, cert, pkey, hash)
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}
		fmt.Printf("unpacked\n")
		os.Exit(0)
	case "info":
		info(source, cert, pkey, hash)
		os.Exit(0)

	default:
		fmt.Println("use -i_want!")
		os.Exit(-1)
	}

}
func szip (source string, destination string, cert string, pkey string) error {
	zipBuf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(zipBuf)
	var meta []FileMeta
	err := ZipFileWriter(source, filepath.Base(source) + "/", zipWriter, &meta)
	if err != nil {
		return err
	}
	err = zipWriter.Close()
	if err != nil {
		return err
	}
    jsonMeta, err := json.Marshal(&meta)
    if err != nil {
        return err
    }
	zipMetaBuf := new(bytes.Buffer)
	zipMetaWriter := zip.NewWriter(zipMetaBuf)
	m, err := zipMetaWriter.Create("meta.json")
	if err != nil {
		return err
	}
	_, err = m.Write(jsonMeta)
	if err != nil {
		return err
	}
	err = zipMetaWriter.Close()
	if err != nil {
		return err
	}
	metaSize := new(bytes.Buffer)
	err = binary.Write(metaSize, binary.BigEndian, uint32(binary.Size(zipMetaBuf.Bytes())))
	if err != nil {
		return err
	}
	stufToSign := append(metaSize.Bytes(), zipMetaBuf.Bytes()...)
	stufToSign = append(stufToSign, zipBuf.Bytes()...)
	err = SignArchive(stufToSign, destination, filepath.Base(source) + ".szp", cert, pkey)
	if err != nil {
		return err
	}
	return nil
}
func extract(source string, destination string, cert string, pkey string, hash string) error {
	err, sign := CheckSZP(source, cert, pkey, hash)
	if err != nil {
		return err
	}
	err, fileMetas := GetMeta(sign)
	if err != nil {
		return err
	}
	metaSize := int64(binary.BigEndian.Uint32(sign.Content[:4]))
	
	bytedArchive := bytes.NewReader(sign.Content[4+metaSize:])

	zipReader, err := zip.NewReader(bytedArchive, bytedArchive.Size()) 
	if err != nil {
		return err
	}

	err = ZipFileReader(zipReader, fileMetas, destination)
	if err != nil {
		return err
	}
	return nil
}

func info(source string, cert string, pkey string, hash string) error{
	err, sign := CheckSZP(source, cert, pkey, hash)
	if err != nil {
		return err
	}

	err, fileMetas := GetMeta(sign)
	if err != nil {
		return err
	}

	for _, file := range fileMetas {
		fmt.Printf("%+v\n", file)
	}

	return nil
}

func CheckSZP(source string, cert string, pkey string, hash string) (error, *pkcs7.PKCS7) {
	szp, err := ioutil.ReadFile(source)
	if err != nil {
		return err, nil
	}

	sign, err := pkcs7.Parse(szp)
	if err != nil {
		return err, nil
	}

	err = sign.Verify()
	if err != nil {
		return err, nil
	}

	signer := sign.GetOnlySigner()
	if signer == nil {
		return errors.New("error with signer"), nil
	}

	if hash != "UNDEF" {
		if hash != fmt.Sprintf("%x", sha1.Sum(signer.Raw)) {
			fmt.Println(fmt.Sprintf("%x", sha1.Sum(signer.Raw)))
			return errors.New("error with hash cert"), nil
		}
	}

	certificate, err := tls.LoadX509KeyPair(cert, pkey)
	if err != nil {
		return err, nil
	}

	rsaCert, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return err, nil
	}

	if bytes.Compare(rsaCert.Raw, signer.Raw) != 0 {
		return errors.New("error cirt not match"), nil
	}
	return nil, sign
}

func GetMeta(p *pkcs7.PKCS7) (error, []FileMeta) {
	metaSize := int64(binary.BigEndian.Uint32(p.Content[:4]))
	bytedMeta := bytes.NewReader(p.Content[4:metaSize+4])

	readableMeta, err := zip.NewReader(bytedMeta, bytedMeta.Size())
	if err != nil {
		return err, nil
	}

	metaCompressed := readableMeta.File[0] //meta.json

	metaUncompressed, err := metaCompressed.Open()
	if err != nil {
		return err, nil
	}
	defer metaUncompressed.Close()

	var fileMetas []FileMeta
	metaUncompressedBody, err := ioutil.ReadAll(metaUncompressed)
	if err != nil {
		return err, nil
	}
	err = json.Unmarshal(metaUncompressedBody, &fileMetas)
	if err != nil {
		return err, nil
	}

	return nil, fileMetas
}

type FileMeta struct {
	Name string `json:"name"`
	OriginalSize uint64 `json:"original_size"`
	CompressedSize uint64 `json:"compressed_size"`
	ModTime string `json:"mod_time"`
	Sha1Hash [20]byte `json:"sha1_hash"`
}

func FileToMeta(header *zip.FileHeader, fileBody []byte) (FileMeta){
	fileMeta := FileMeta{
		Name: header.Name,
		OriginalSize: header.UncompressedSize64,
		CompressedSize: header.CompressedSize64,
		ModTime: header.Modified.Format("Monday, 02-Jan-06 15:04:05 MST"),
		Sha1Hash: sha1.Sum(fileBody),
	}

	return fileMeta
}

func ZipFileWriter(source string, pathTrace string, zipWriter *zip.Writer, meta *[]FileMeta) error {

	filesToWrite, err := ioutil.ReadDir(source)
    if err != nil {
        return err
    }

    zipWriter.Create(pathTrace)

	for _, file := range filesToWrite {
		if file.IsDir(){
			ZipFileWriter(source + "/" + file.Name(), pathTrace + file.Name() + "/", zipWriter, meta)
		} else {
			f, err := zipWriter.Create(pathTrace + file.Name())
			if err != nil {
	            return err
	        }

	        fileBody, err := ioutil.ReadFile(filepath.Join(source, file.Name()))
	        if err != nil {
	            return err
	        }

	        _, err = f.Write(fileBody)
	        if err != nil {
	            return err
	        }

	        fileHeader, err := zip.FileInfoHeader(file)
	        if err != nil {
	            return err
	        }

	        *meta = append(*meta, FileToMeta(fileHeader, fileBody))
		}
		
	}

	return nil
}

func ZipFileReader(zipReader *zip.Reader, fileMetas []FileMeta, destination string) error{
	for _, file := range zipReader.File {
		fileContent, err := file.Open()
		if err != nil {
			return err
		}

		fileBody, err := ioutil.ReadAll(fileContent)
		if err != nil {
			return err
		}

		for _, meta := range fileMetas{
			if meta.Name == filepath.Base(file.Name) {
				fileHash := sha1.Sum(fileBody)
				if meta.Sha1Hash != fileHash {
					return errors.New("error damaged hash" + file.Name)
				}
			}
		}

		fileInfo := file.FileInfo()
		if fileInfo.IsDir() {
			_, err := os.Stat(filepath.Join(destination, file.Name)) 
			if os.IsNotExist(err) {
			    os.MkdirAll(filepath.Join(destination, file.Name), os.ModePerm)
			} else {
				return errors.New("error Folder " + file.Name + " already exists")
			}
		} else {
			f, err := os.Create(filepath.Join(destination, file.Name))
			if err != nil {
				return err
			}
			defer f.Close()
			_, err = f.Write(fileBody)
			if err != nil {
				return err
			}
		}

		fileContent.Close()
	}

	return nil
}

func SignArchive(stufToSign []byte, destination string, name string, cert string, pkey string) error {
	signedData, err := pkcs7.NewSignedData(stufToSign)
	if err != nil {
	    return err
	}

	certificate, err := tls.LoadX509KeyPair(cert, pkey)
	if err != nil {
		return err
	}

	rsaPKey := certificate.PrivateKey
	rsaCert, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return err
	}

	err = signedData.AddSigner(rsaCert, rsaPKey, pkcs7.SignerInfoConfig{}) 
	if err != nil {
	    return err
	}

	szip, err := signedData.Finish()
	if err != nil {
	    return err
	}

	fmt.Printf("cirt hash: %x\n", sha1.Sum(rsaCert.Raw))

	szpFile, err := os.Create(filepath.Join(destination, name))
	if err != nil {
	    return err
	}
	defer szpFile.Close()
	
	_, err = szpFile.Write(szip)
	if err != nil {
		return err
	}

	return nil
}