package data // import "code.hooto.com/lessos/lospack/server/data"

import (
	"fmt"

	"code.hooto.com/lessos/lessio/filesystem"
	"github.com/lessos/lessdb/sskv/goleveldb"
	// "code.hooto.com/lessos/lessio/connector"
	"code.hooto.com/lessos/lessio/objectx"
	"code.hooto.com/lessos/lospack/server/config"
	"code.hooto.com/lessos/storx/localfs"
)

var (
	err     error
	Data    objectx.Connector
	Storage filesystem.Connector
)

func Init() error {

	//
	opts := config.Config.IoConnectors.Options("database")
	if opts == nil {
		return fmt.Errorf("No IoConnector (%s) Found", "database")
	}
	if Data, err = goleveldb.Open(*opts); err != nil {
		return fmt.Errorf("Can Not Connect To %s, Error: %s", "database", err.Error())
	}

	//
	opts = config.Config.IoConnectors.Options("storage")
	if opts == nil {
		return fmt.Errorf("Can Not Connect To %s", "storage")
	}

	if Storage, err = localfs.Open(*opts); err != nil {
		return fmt.Errorf("Can Not Connect To %s, Error: %s", "storage", err.Error())
	}

	return nil
}
