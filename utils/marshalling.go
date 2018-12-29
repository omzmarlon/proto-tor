package utils

import (
	"encoding/json"
)

func Marshall(data interface{}) ([]byte, error) {
	bytes, err := json.Marshal(data)
	if err != nil {
		return []byte{}, err
	}
	return bytes, nil
}

func UnMarshall(data []byte, e interface{}) error {
	return json.Unmarshal(data, e)
}