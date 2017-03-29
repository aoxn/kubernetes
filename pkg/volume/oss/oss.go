/*
Copyright 2014 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package oss

import (
	"fmt"
	"os"
	"runtime"
	str "strings"

	"github.com/golang/glog"
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/api/v1"
	"k8s.io/kubernetes/pkg/types"
	"k8s.io/kubernetes/pkg/util/exec"
	"k8s.io/kubernetes/pkg/util/mount"
	"k8s.io/kubernetes/pkg/util/strings"
	"k8s.io/kubernetes/pkg/volume"
)

// This is the primary entrypoint for volume plugins.
// The volumeConfig arg provides the ability to configure recycler behavior.  It is implemented as a pointer to allow nils.
// The ossPlugin is used to store the volumeConfig and give it, when needed, to the func that creates OSS Recyclers.
// Tests that exercise recycling should not use this func but instead use ProbeRecyclablePlugins() to override default behavior.
func ProbeVolumePlugins(volumeConfig volume.VolumeConfig) []volume.VolumePlugin {
	return []volume.VolumePlugin{
		&ossPlugin{
			host:   nil,
			config: volumeConfig,
		},
	}
}

type ossPlugin struct {
	host   volume.VolumeHost
	config volume.VolumeConfig
	mounter mount.Interface
}

var _ volume.VolumePlugin = &ossPlugin{}
var _ volume.PersistentVolumePlugin = &ossPlugin{}
var _ volume.RecyclableVolumePlugin = &ossPlugin{}

const (
	ossPluginName = "kubernetes.io/oss"
)

func (plugin *ossPlugin) Init(host volume.VolumeHost) error {
	plugin.host = host
	plugin.mounter = &Mounter{}
	return nil
}

func (plugin *ossPlugin) GetPluginName() string {
	return ossPluginName
}

func (plugin *ossPlugin) GetVolumeName(spec *volume.Spec) (string, error) {
	volumeSource, _, err := getVolumeSource(spec)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf(
		"%v/%v",
		volumeSource.Endpoint,
		volumeSource.Bucket), nil
}

func (plugin *ossPlugin) CanSupport(spec *volume.Spec) bool {
	return (spec.PersistentVolume != nil && spec.PersistentVolume.Spec.OSS != nil) ||
		(spec.Volume != nil && spec.Volume.OSS != nil)
}

func (plugin *ossPlugin) RequiresRemount() bool {
	return true
}

func (plugin *ossPlugin) GetAccessModes() []v1.PersistentVolumeAccessMode {
	return []v1.PersistentVolumeAccessMode{
		v1.ReadWriteOnce,
		v1.ReadOnlyMany,
		v1.ReadWriteMany,
	}
}

func (plugin *ossPlugin) NewMounter(spec *volume.Spec, pod *v1.Pod, _ volume.VolumeOptions) (volume.Mounter, error) {
	return plugin.newMounterInternal(spec, pod, plugin.mounter)
}

func (plugin *ossPlugin) newMounterInternal(spec *volume.Spec, pod *v1.Pod, mounter mount.Interface) (volume.Mounter, error) {
	source, readOnly, err := getVolumeSource(spec)
	if err != nil {
		return nil, err
	}

	return &ossMounter{
		oss: &oss{
			volName: spec.Name(),
			mounter: mounter,
			pod:     pod,
			plugin:  plugin,
		},
		server:     source.Endpoint,
		exportPath: source.Bucket,
		readOnly:   readOnly,
	}, nil
}

func (plugin *ossPlugin) NewUnmounter(volName string, podUID types.UID) (volume.Unmounter, error) {
	return plugin.newUnmounterInternal(volName, podUID, plugin.mounter)
}

func (plugin *ossPlugin) newUnmounterInternal(volName string, podUID types.UID, mounter mount.Interface) (volume.Unmounter, error) {
	return &ossUnmounter{&oss{
		volName: volName,
		mounter: mounter,
		pod:     &v1.Pod{ObjectMeta: v1.ObjectMeta{UID: podUID}},
		plugin:  plugin,
	}}, nil
}

func (plugin *ossPlugin) NewRecycler(pvName string, spec *volume.Spec, eventRecorder volume.RecycleEventRecorder) (volume.Recycler, error) {
	return newRecycler(pvName, spec, eventRecorder, plugin.host, plugin.config)
}

func (plugin *ossPlugin) ConstructVolumeSpec(volumeName, mountPath string) (*volume.Spec, error) {
	ossVolume := &v1.Volume{
		Name: volumeName,
		VolumeSource: v1.VolumeSource{
			OSS: &v1.OSSVolumeSource{
				Bucket: volumeName,
			},
		},
	}
	return volume.NewSpecFromVolume(ossVolume), nil
}

// OSS volumes represent a bare host file or directory mount of an OSS export.
type oss struct {
	volName string
	pod     *v1.Pod
	mounter mount.Interface
	plugin  *ossPlugin
	volume.MetricsNil
}

func (ossVolume *oss) GetPath() string {
	name := ossPluginName
	return ossVolume.plugin.host.GetPodVolumeDir(ossVolume.pod.UID, strings.EscapeQualifiedNameForDisk(name), ossVolume.volName)
}

// Checks prior to mount operations to verify that the required components (binaries, etc.)
// to mount the volume are available on the underlying node.
// If not, it returns an error
func (ossMounter *ossMounter) CanMount() error {
	exe := exec.New()
	switch runtime.GOOS {
	case "linux":
		_, err1 := exe.Command("which", "ossfs").CombinedOutput()

		if err1 != nil {
			return fmt.Errorf("Required binary /usr/local/bin/ossfs is missing")
		}
		return nil
	case "darwin":

		return fmt.Errorf("Unsuported Arch Darwin")
	}
	return nil
}

type ossMounter struct {
	*oss
	server     string
	exportPath string
	readOnly   bool
	options    string
}

var _ volume.Mounter = &ossMounter{}

func (b *ossMounter) GetAttributes() volume.Attributes {
	return volume.Attributes{
		ReadOnly:        str.Contains(b.options,"default_acl=public-read"),
		Managed:         false,
		SupportsSELinux: false,
	}
}

// SetUp attaches the disk and bind mounts to the volume path.
func (b *ossMounter) SetUp(fsGroup *int64) error {
	return b.SetUpAt(b.GetPath(), fsGroup)
}

func (b *ossMounter) SetUpAt(dir string, fsGroup *int64) error {
	notMnt, err := b.mounter.IsLikelyNotMountPoint(dir)
	glog.V(4).Infof("OSS mount set up: %s %v %v", dir, !notMnt, err)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if !notMnt {
		return nil
	}
	os.MkdirAll(dir, 0750)
	err = b.mounter.Mount(b.exportPath, dir, "oss", b.parseOptions())
	if err != nil {
		notMnt, mntErr := b.mounter.IsLikelyNotMountPoint(dir)
		if mntErr != nil {
			glog.Errorf("IsLikelyNotMountPoint check failed: %v", mntErr)
			return err
		}
		if !notMnt {
			if mntErr = b.mounter.Unmount(dir); mntErr != nil {
				glog.Errorf("Failed to unmount: %v", mntErr)
				return err
			}
			notMnt, mntErr := b.mounter.IsLikelyNotMountPoint(dir)
			if mntErr != nil {
				glog.Errorf("IsLikelyNotMountPoint check failed: %v", mntErr)
				return err
			}
			if !notMnt {
				// This is very odd, we don't expect it.  We'll try again next sync loop.
				glog.Errorf("%s is still mounted, despite call to unmount().  Will try again next sync loop.", dir)
				return err
			}
		}
		os.Remove(dir)
		return err
	}
	return nil
}

func (b *ossMounter) parseOptions()[]string{

	options := []string{}
	// b.options is the string with format opt1=val1,opt2=val2,opt3=val3  colon separated.
	for _,v := range str.Split(b.options,","){
		if v == ""{
			continue
		}
		options = append(options,fmt.Sprintf("-o%s",v))
	}
	if b.server != "" {
		options = append(options, fmt.Sprintf("-ourl=%s",b.server))
	}
	return options
}

//
//func (c *ossUnmounter) GetPath() string {
//	name := ossPluginName
//	return c.plugin.host.GetPodVolumeDir(c.pod.UID, strings.EscapeQualifiedNameForDisk(name), c.volName)
//}

var _ volume.Unmounter = &ossUnmounter{}

type ossUnmounter struct {
	*oss
}

func (c *ossUnmounter) TearDown() error {
	return c.TearDownAt(c.GetPath())
}

func (c *ossUnmounter) TearDownAt(dir string) error {
	notMnt, err := c.mounter.IsLikelyNotMountPoint(dir)
	if err != nil {
		glog.Errorf("Error checking IsLikelyNotMountPoint: %v", err)
		return err
	}
	if notMnt {
		return os.Remove(dir)
	}

	if err := c.mounter.Unmount(dir); err != nil {
		glog.Errorf("Unmounting failed: %v", err)
		return err
	}
	notMnt, mntErr := c.mounter.IsLikelyNotMountPoint(dir)
	if mntErr != nil {
		glog.Errorf("IsLikelyNotMountPoint check failed: %v", mntErr)
		return mntErr
	}
	if notMnt {
		if err := os.Remove(dir); err != nil {
			return err
		}
	}

	return nil
}

func newRecycler(pvName string, spec *volume.Spec, eventRecorder volume.RecycleEventRecorder, host volume.VolumeHost, volumeConfig volume.VolumeConfig) (volume.Recycler, error) {
	if spec.PersistentVolume == nil || spec.PersistentVolume.Spec.OSS == nil {
		return nil, fmt.Errorf("spec.PersistentVolumeSource.OSS is nil")
	}
	return &ossRecycler{
		name:          spec.Name(),
		server:        spec.PersistentVolume.Spec.OSS.Endpoint,
		path:          spec.PersistentVolume.Spec.OSS.Bucket,
		host:          host,
		config:        volumeConfig,
		timeout:       volume.CalculateTimeoutForVolume(volumeConfig.RecyclerMinimumTimeout, volumeConfig.RecyclerTimeoutIncrement, spec.PersistentVolume),
		pvName:        pvName,
		eventRecorder: eventRecorder,
	}, nil
}

// ossRecycler scrubs an OSS volume by running "rm -rf" on the volume in a pod.
type ossRecycler struct {
	name    string
	server  string
	path    string
	host    volume.VolumeHost
	config  volume.VolumeConfig
	timeout int64
	volume.MetricsNil
	pvName        string
	eventRecorder volume.RecycleEventRecorder
}

func (r *ossRecycler) GetPath() string {
	return r.path
}

// Recycle recycles/scrubs clean an OSS volume.
// Recycle blocks until the pod has completed or any error occurs.
func (r *ossRecycler) Recycle() error {
	templateClone, err := api.Scheme.DeepCopy(r.config.RecyclerPodTemplate)
	if err != nil {
		return err
	}
	pod := templateClone.(*v1.Pod)
	// overrides
	pod.Spec.ActiveDeadlineSeconds = &r.timeout
	pod.GenerateName = "pv-recycler-oss-"
	pod.Spec.Volumes[0].VolumeSource = v1.VolumeSource{
		OSS: &v1.OSSVolumeSource{
			Endpoint: r.server,
			Bucket:   r.path,
		},
	}
	return volume.RecycleVolumeByWatchingPodUntilCompletion(r.pvName, pod, r.host.GetKubeClient(), r.eventRecorder)
}

func getVolumeSource(spec *volume.Spec) (*v1.OSSVolumeSource, bool, error) {
	if spec.Volume != nil && spec.Volume.OSS != nil {
		//return spec.Volume.OSS, spec.Volume.OSS.ReadOnly, nil
		return spec.Volume.OSS, false, nil
	} else if spec.PersistentVolume != nil &&
		spec.PersistentVolume.Spec.OSS != nil {
		return spec.PersistentVolume.Spec.OSS, spec.ReadOnly, nil
	}

	return nil, false, fmt.Errorf("Spec does not reference a OSS volume type")
}
