package oss

import (
	"k8s.io/kubernetes/pkg/util/mount"
	"fmt"
	"github.com/golang/glog"
	"os/exec"
	"os"
	"syscall"
	"errors"
	"bufio"
	"k8s.io/kubernetes/pkg/cloudprovider/providers/alicloud"
	"encoding/json"
	"strings"
)

var DEFAULT_OSSFS_PASSWDFILE = "/etc/passwd-ossfs"
var DEFAULT_CLOUD_CONFIGFILE = "/etc/kubernetes/cloud-config"
var MOUNT = "ossfs"

type Mounter struct {
}


func (m *Mounter) Mount(source string, target string, fstype string, options []string) error{
	if err:= withPasswdFile(source); err != nil {
		return err
	}
	mntOptions := append([]string{source,target},options...)
	glog.V(4).Infof("Mounting cmd (%s) with arguments (%s)", MOUNT, mntOptions)
	command := exec.Command(MOUNT, mntOptions...)
	output, err := command.CombinedOutput()
	if err != nil {

		glog.Errorf("Error Mount ossfs: cmd=[%s] output=[%s]",strings.Join(command.Args," "),string(output))
		return fmt.Errorf("mount failed: %v\nMounting command: %s\nMounting arguments: %s %s %s %v\nOutput: %s\n",
			err, MOUNT, source, target, fstype, options, string(output))
	}
	return nil
}

func withPasswdFile(bucket string) error{
	token,err := readKeySecret(bucket)
	if err != nil {
		return err
	}

	pass,err := os.OpenFile(DEFAULT_OSSFS_PASSWDFILE,os.O_RDWR|os.O_CREATE,0640)
	if err != nil{
		return err
	}
	defer pass.Close()

	scan := bufio.NewScanner(pass)
	for scan.Scan() {
		if token == scan.Text(){
			return nil
		}
	}
	if err := scan.Err(); err != nil {
		return err
	}
	if _,err := pass.Write([]byte(fmt.Sprintf("%s\n",token)));err != nil {
		return err
	}
	return nil
}

func readKeySecret(bucket string) (string,error){
	var cfg alicloud.CloudConfig
	if cloud,err := os.Open(DEFAULT_CLOUD_CONFIGFILE);err != nil {
		return "",err
	}else {
		defer cloud.Close()
		if err := json.NewDecoder(cloud).Decode(&cfg); err != nil {
			return "", err
		}
	}
	return fmt.Sprintf("%s:%s:%s",bucket,cfg.Global.AccessKeyID,cfg.Global.AccessKeySecret),nil
}

// Unmount unmounts given target.
func (m *Mounter) Unmount(target string) error{
	glog.V(4).Infof("OSS Unmounting %s", target)
	command := exec.Command("umount", target)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Unmount failed: %v\nUnmounting arguments: %s\nOutput: %s\n", err, target, string(output))
	}
	return nil
}
// List returns a list of all mounted filesystems.  This can be large.
// On some platforms, reading mounts is not guaranteed consistent (i.e.
// it could change between chunked reads). This is guaranteed to be
// consistent.
func (m *Mounter) List() ([]mount.MountPoint, error){
	return []mount.MountPoint{},errors.New("Unimplemented")
}
// IsLikelyNotMountPoint determines if a directory is a mountpoint.
// It should return ErrNotExist when the directory does not exist.
func (m *Mounter) IsLikelyNotMountPoint(file string) (bool, error){
	return IsNotMountPoint(file)
}

func IsNotMountPoint(file string) (bool, error) {
	stat, err := os.Stat(file)
	if err != nil {
		return true, err
	}
	rootStat, err := os.Lstat(file + "/..")
	if err != nil {
		return true, err
	}
	// If the directory has a different device as parent, then it is a mountpoint.
	if stat.Sys().(*syscall.Stat_t).Dev != rootStat.Sys().(*syscall.Stat_t).Dev {
		return false, nil
	}

	return true, nil
}


// DeviceOpened determines if the device is in use elsewhere
// on the system, i.e. still mounted.
func (m *Mounter) DeviceOpened(pathname string) (bool, error){
	return false, errors.New("Unimplemented")
}
// PathIsDevice determines if a path is a device.
func (m *Mounter) PathIsDevice(pathname string) (bool, error){
	return false, errors.New("Unimplemented")
}
// GetDeviceNameFromMount finds the device name by checking the mount path
// to get the global mount path which matches its plugin directory
func (m *Mounter) GetDeviceNameFromMount(mountPath, pluginDir string) (string, error){
	return "", errors.New("Unimplemented")
}