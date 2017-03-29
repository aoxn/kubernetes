package oss

import (
	"strings"
	"testing"
	"fmt"
	"os"
)

func TestParseOption(t *testing.T){
	mnt := &ossMounter{options:"opt1=val1,opt2=val2,opt3=val3"}
	s := strings.Join(mnt.parseOptions(),",")
	if !strings.EqualFold(s,"-oopt1=val1,-oopt2=val2,-oopt3=val3"){
		t.Fatal("ParseOption Failed: ",s)
	}
	mnt.options = ""
	s = strings.Join(mnt.parseOptions(),",")
	fmt.Fprintf(os.Stderr,"[%s]",s)
	if !strings.EqualFold(s,""){
		t.Fatal("ParseOption Failed: ",s)
	}
}
