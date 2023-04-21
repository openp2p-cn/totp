// Time-based One-time Password
package totp

import (
	"testing"
	"time"
)

func TestTOTP(t *testing.T) {
	tt := TOTP{Step: RelayTOTPStep}
	for i := 0; i < 20; i++ {
		ts := time.Now().Unix()
		code := tt.Gen(13666999958022769123, ts)
		t.Log(code)
		if !tt.Verify(code, 13666999958022769123, ts) {
			t.Error("TOTP error")
		}
		if !tt.Verify(code, 13666999958022769123, ts-10) {
			t.Error("TOTP error")
		}
		if !tt.Verify(code, 13666999958022769123, ts+10) {
			t.Error("TOTP error")
		}
		if tt.Verify(code, 13666999958022769123, ts+60) {
			t.Error("TOTP error")
		}
		if tt.Verify(code, 13666999958022769124, ts+1) {
			t.Error("TOTP error")
		}
		if tt.Verify(code, 13666999958022769125, ts+1) {
			t.Error("TOTP error")
		}
		time.Sleep(time.Second)
		t.Log("round", i, " ", ts, " test ok")
	}

}
