package libcalico

import (
	"github.com/coreos/etcd/client"
	"fmt"
	"golang.org/x/net/context"
)

type Workload struct {
	Hostname       string `json:"-"`
	OrchestratorID string `json:"-"`
	WorkloadID     string `json:"-"`
}

func (w *Workload) Delete(etcd client.KeysAPI) error {
	key := fmt.Sprintf("/calico/v1/host/%s/workload/%s/%s", w.Hostname, w.OrchestratorID, w.WorkloadID)

	if _, err := etcd.Delete(context.Background(), key, &client.DeleteOptions{Recursive:true, Dir:true}); err != nil {
		return err
	}
	return nil
}
