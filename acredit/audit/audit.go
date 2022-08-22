package audit

import (
	"bytes"
	"errors"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

type Device struct {
	Ip       string
	Username string
	Passwrd  string
}

func GetConfigurations(device *Device) ([]string, error) {
	var results []string
	config := &ssh.ClientConfig{
		User: device.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(device.Passwrd),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", device.Ip+":22", config)
	if err != nil {
		return results, err
	}
	defer client.Close()

	check_weak_password := "egrep 'minlen=12.*ucredit=-1.*lcredit=-1.*dcredit=-1.*ocredit=-1' /etc/pam.d/common-password --count"
	check_blacklist_password := "egrep 'reject_username.*dictcheck=1.*badwords=NATO' /etc/pam.d/common-password --count"
	check_10_generations_password := "egrep 'pam_pwhistory.so.*remember=10' /etc/pam.d/common-password --count"
	check_hiden_auth := "sudo egrep 'pwfeedback' /etc/sudoers"
	check_hashed_password := "grep pam_unix.so /etc/pam.d/common-password"
	check_inactive_after_90 := "grep '^INACTIVE=90$' /etc/default/useradd"
	check_is_using_anti_malware := "dpkg -l | egrep -cE 'rkhunter |clamav |chkrootkit '"
	check_how_long_passwords_are_valid := "grep '^PASS_MAX_DAYS' /etc/login.defs"
	check_logs_account := "[[ -f /var/log/auth.log ]] && echo 'auth.log file exists'"
	check_updates_anti_malware := " sudo grep '^Check' /etc/clamav/freshclam.conf ; dpkg -l | grep -o 'clamav-freshclam'"
	check_hypervisor := "sudo dmidecode | grep -i  -e 'Product Name:'"
	check_secure_email_gateway := "dpkg -l | grep -coE 'mailscanner'"
	check_removable_storage := "egrep -ce '^blacklist usb_storage' /etc/modprobe.d/blacklist.conf ; stat -c '%a' /media"
	cmd := []string{
		check_weak_password,
		check_blacklist_password,
		check_10_generations_password,
		check_hiden_auth,
		check_hashed_password,
		check_inactive_after_90,
		check_is_using_anti_malware,
		check_how_long_passwords_are_valid,
		check_logs_account,
		check_updates_anti_malware,
		check_hypervisor,
		check_secure_email_gateway,
		check_removable_storage,
	}
	for _, command := range cmd {

		session, err := client.NewSession()
		if err != nil {
			return results, err
		}
		defer session.Close()
		var out bytes.Buffer
		session.Stdout = &out
		err = session.Run(command)
		if err != nil {
			results = append(results, err.Error())

		} else {
			results = append(results, out.String())
		}

	}
	return results, nil
}
func verifyWeakPassword(result string) error {

	matched, _ := regexp.MatchString("Process exited with status 1", result)
	if matched == true {
		return errors.New("IAM4-1: Password complexity security rule is not met!")
	}

	val, err := strconv.ParseInt(result[:len(result)-1], 10, 64)
	if err != nil {
		return err
	}
	if val != 1 {
		return errors.New("IAM4-1: Password complexity security rule is not met!")
	}
	return nil
}
func verifyBlacklistPassword(result string) error {

	matched, _ := regexp.MatchString("Process exited with status 1", result)
	if matched == true {
		return errors.New("IAM4-2: Password complexity security rule is not met!")
	}
	val, err := strconv.ParseInt(result[:len(result)-1], 10, 64)
	if err != nil {
		return err
	}
	if val != 1 {
		return errors.New("IAM4-2:Password complexity security rule is not met!")
	}
	return nil
}
func verify10Genetarions(result string) error {
	matched, _ := regexp.MatchString("Process exited with status 1", result)
	if matched == true {
		return errors.New("IAM4-6: The system does not keep a history of passwords!")
	}
	val, err := strconv.ParseInt(result[:len(result)-1], 10, 64)
	if err != nil {
		return err
	}
	if val != 1 {
		return errors.New("IAM4-6: The system does not keep a history of passwords!")
	}
	return nil
}
func verifyHidenAuth(result string) error {
	matched, _ := regexp.MatchString("Process exited with status 1", result)
	if matched == true {
		return errors.New("IAM3-6: Password is not using Asterisks")
	}
	matched, _ = regexp.MatchString("pwfeedback", result)
	if matched == false {
		return errors.New("IAM3-6: Password is not using Asterisks")
	}
	return nil

}
func verifyHashedPasssowd(result string) error {
	matched, _ := regexp.MatchString("Process exited with status 1", result)
	if matched == true {
		return errors.New("IAM4-8: Stored password are not hashed")
	}
	if (strings.Contains(result, "sha512") || strings.Contains(result, "sha256") ||
		strings.Contains(result, "yescrypt") || strings.Contains(result, "md5") || strings.Contains(result, "bigcrypt")) && strings.Contains(result, "pam_unix.so") == false {
		return errors.New("IAM4-8: Stored password are not hashed")
	}
	return nil
}
func verifyInactiveAfter90(result string) error {
	matched, _ := regexp.MatchString("Process exited with status 1", result)
	if matched == true {
		return errors.New("IAM8-4: Accounts are not disabled after 90 days of inactivity")
	}
	if strings.Contains(result, "90") == false || strings.Contains(result, "#") == true {
		return errors.New("IAM8-4: Accounts are not disabled after 90 days of inactivity")
	}
	return nil
}
func verifyUsingAntiMalware(result string) error {
	matched, _ := regexp.MatchString("Process exited with status 1", result)
	if matched == true {
		return errors.New("PSW3-1 and PSW3-2: The instance doesn't use anti-malware and variety of anti-malware is not used")
	}
	val, err := strconv.ParseInt(result[:len(result)-1], 10, 64)
	if err != nil {
		return err
	}
	if val == 0 {
		return errors.New("PSW3-1: The instance doesn't use anti-malware")
	} else if val < 2 {
		return errors.New("PSW3-2: A variety of anti-malware is not used")
	}
	return nil
}
func verifyHowLongPasswordsAreValid(result string) error {
	matched, _ := regexp.MatchString("Process exited with status 1", result)
	if matched == true {
		return errors.New("IAM4-4 or IAM4-5:Password expiration rule is not configured")
	}
	if strings.Contains(result, "365") == false {
		return errors.New("IAM4-4 or IAM4-5:Password expiration rule is not configured")
	}
	return nil
}

func verifyLogsAccount(result string) error {
	matched, _ := regexp.MatchString("Process exited with status 1", result)
	if matched == true {
		return errors.New("IAM8-1: Istance does not logs account creation, modification, enabling; and privilege elevation, disabling and removal")
	}
	if strings.Contains(result, "auth.log file exists") == false {
		return errors.New("IAM8-1: Istance does not logs account creation, modification, enabling; and privilege elevation, disabling and removal")
	}
	return nil

}
func verifyUpdatedAntiMalware(result string) error {
	matched, _ := regexp.MatchString("Process exited with status 1", result)
	if matched == true {
		return errors.New("PSW3-4: The instance is not updated every 24 hours")
	}
	updates_informations := strings.Split(result, "\n")
	re := regexp.MustCompile("[0-9]+")
	daily_update := re.FindAllString(updates_informations[0], 10)[0]
	val, err := strconv.ParseInt(daily_update, 10, 64)
	if err != nil {
		return err
	}

	if val != 1 && updates_informations[1] != "clamav-freshclam" {
		return errors.New("PSW3-4: The instance is not updated every 24 hours")
	}

	return nil

}
func verifyHypervisor(result string) error {
	// list of Hypervisors type 2
	type_2 := [7]string{"Oracle VM Server", "Parallels", "VMWare Player", "VMware Fusion", "VMware Workstation", "VMware Server", "VirtualBox"}
	for _, hypervisor_type := range type_2 {
		if strings.Contains(result, hypervisor_type) == true {
			return errors.New("POS2-2: Instance is using Hypervisor type 2")
		}

	}
	return nil
}
func verifySecureEmailGateway(result string) error {
	matched, _ := regexp.MatchString("Process exited with status 1", result)
	if matched == true {
		return errors.New("POS6-1: Istnace is not using Message Content Filtering")
	}
	val, err := strconv.ParseInt(result[:len(result)-1], 10, 64)
	if err != nil {
		return err
	}
	if val == 0 {
		return errors.New("POS6-1: Istnace is not using Message Content Filtering")
	}
	return nil

}
func verifyRemovableStorage(result string) error {
	responds := strings.Split(result, "\n")
	usb_information, err := strconv.ParseInt(responds[0], 10, 64)
	if err != nil {
		return err
	}

	cd_dvd_floppy_information, err := strconv.ParseInt(responds[1], 10, 64)
	if err != nil {
		return err
	}
	if usb_information != 1 || cd_dvd_floppy_information != 555 {
		return errors.New("CS6-4: Istance is able to use USB, CD, DVD, Floppy discs")
	}
	return nil

}

func VerifyAllRules(device *Device) error {

	results, err := GetConfigurations(device)
	if err != nil {
		return err
	}

	err = verifyWeakPassword(results[0])
	if err != nil {
		return err
	}
	err = verifyBlacklistPassword(results[1])
	if err != nil {
		return err
	}
	err = verify10Genetarions(results[2])
	if err != nil {
		return err
	}
	err = verifyHidenAuth(results[3])
	if err != nil {
		return err
	}
	err = verifyHashedPasssowd(results[4])
	if err != nil {
		return err
	}
	err = verifyInactiveAfter90(results[5])
	if err != nil {
		return err
	}
	err = verifyUsingAntiMalware(results[6])
	if err != nil {
		return err
	}

	err = verifyHowLongPasswordsAreValid(results[7])
	if err != nil {
		return err
	}

	err = verifyLogsAccount(results[8])
	if err != nil {
		return err
	}

	err = verifyUpdatedAntiMalware(results[9])
	if err != nil {
		return err
	}
	err = verifyHypervisor(results[10])
	if err != nil {
		return err
	}
	err = verifySecureEmailGateway(results[11])
	if err != nil {
		return err
	}

	err = verifyRemovableStorage(results[12])
	if err != nil {
		return err
	}

	return nil

}
