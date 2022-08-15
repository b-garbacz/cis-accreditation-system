package audit

import (
	"bytes"
	"errors"
	"log"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

/*
	Structure of tested device
*/
type Device struct {
	Ip       string
	Username string
	Passwrd  string
	Version  string
}

// Get instance operating system
func Get_version_name(device *Device) error {
	config := &ssh.ClientConfig{
		User: device.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(device.Passwrd),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", device.Ip+":22", config)
	if err != nil {
		return err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	data, err := session.CombinedOutput("lsb_release -d")
	if err != nil {
		if _, ok := err.(*ssh.ExitError); ok == true {
			return errors.New(string(data))
		}
	}
	version := strings.Split(string(data), "\t")
	device.Version = version[1]
	return nil

}

//IAM
func check_weak_password(device *Device) error {
	/*	IAM4-1
		First password contain uppercase,lowercase and  special sign, but  length is less than 12 characters;
		Second password meet the length requirements but it doesn't contain uppercase,lowercase and special sign;

	*/
	config := &ssh.ClientConfig{
		User: device.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(device.Passwrd),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", device.Ip+":22", config)
	if err != nil {
		log.Fatal("Failed to dial: ", err.Error())
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	var b bytes.Buffer
	session.Stdout = &b

	if err := session.Run("egrep 'minlen=12.*ucredit=-1.*lcredit=-1.*dcredit=-1.*ocredit=-1' /etc/pam.d/common-password --count"); err != nil {
		return err
	}

	val, err := strconv.ParseInt(b.String()[:len(b.String())-1], 10, 64)
	if err != nil {
		return err
	}
	if val != 1 {
		return errors.New("Password complexity security rule is not met!")
	}

	return nil
}
func check_blacklist_password(device *Device) error {
	/*	IAM4-2
		First password meets the complexity requirement but also contain word from blacklist - NATO
		Second password meets the complexity requirement but contain pattern from keyboard(This password is also in the rockyou.txt file)
	*/

	config := &ssh.ClientConfig{
		User: device.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(device.Passwrd),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", device.Ip+":22", config)
	if err != nil {
		log.Fatal("Failed to dial: ", err.Error())
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	var b bytes.Buffer
	session.Stdout = &b

	if err := session.Run("egrep 'reject_username.*dictcheck=1.*badwords=NATO' /etc/pam.d/common-password --count"); err != nil {
		return err
	}

	val, err := strconv.ParseInt(b.String()[:len(b.String())-1], 10, 64)
	if err != nil {
		return err
	}
	if val != 1 {
		return errors.New("Password complexity security rule is not met!")
	}
	return nil
}
func check_10_generations_password(device *Device) error {
	/*
		IAM4-6: Password reuse is prohibited for 10 generations (i.e. users cannot re-use their last 10 passwords on a system).
	*/
	config := &ssh.ClientConfig{
		User: device.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(device.Passwrd),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", device.Ip+":22", config)
	if err != nil {
		log.Fatal("Failed to dial: ", err.Error())
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	var b bytes.Buffer
	session.Stdout = &b

	if err := session.Run("egrep 'pam_pwhistory.so.*remember=10' /etc/pam.d/common-password --count"); err != nil {
		return err
	}

	val, err := strconv.ParseInt(b.String()[:len(b.String())-1], 10, 64)
	if err != nil {
		return err
	}
	if val != 1 {
		return errors.New("the system does not keep a history of passwords")
	}

	return nil
}
func check_hiden_auth(device *Device) error {
	/*IAM3-6: Authenticator feedback information is obscured from the user during the authentication process.

	 */
	config := &ssh.ClientConfig{
		User: device.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(device.Passwrd),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", device.Ip+":22", config)
	if err != nil {
		log.Fatal("Failed to dial: ", err.Error())
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		log.Fatal("Failed to create session: ", err.Error())
	}
	defer session.Close()

	var b bytes.Buffer
	session.Stdout = &b

	if err := session.Run("sudo grep Defaults /etc/sudoers"); err != nil {
		log.Fatal("Failed to create session: ", err.Error())
	}

	//split := strings.Split(b.String(), "Defaults")
	matched, _ := regexp.MatchString("pwfeedback", b.String())
	if matched == false {
		return errors.New("Password is not using Asterisks")
	}
	return nil
}
func check_hashed_password(device *Device) error {
	/*
		IAM4-8: The CIS stores only cryptographically protected passwords. Hashed passwords are salted with a unique and unpredictable salt per password.

		User password is stored in /etc/shadows file stores secure user account information including the hashed password. pam_unix.so module is responsible for updating password by using etc/shadow and passwd.
		When a user changes their password then defined hash algorithm as option will be used to encrypt password.
	*/
	config := &ssh.ClientConfig{
		User: device.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(device.Passwrd),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", device.Ip+":22", config)
	if err != nil {
		log.Fatal("Failed to dial: ", err.Error())
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		log.Fatal("Failed to create session: ", err.Error())
	}
	defer session.Close()

	var b bytes.Buffer
	session.Stdout = &b

	if err := session.Run("grep pam_unix.so /etc/pam.d/common-password"); err != nil {
		log.Fatal("Failed to create session: ", err.Error())
	}
	if (strings.Contains(b.String(), "sha512") || strings.Contains(b.String(), "sha256") ||
		strings.Contains(b.String(), "yescrypt") || strings.Contains(b.String(), "md5") || strings.Contains(b.String(), "bigcrypt")) && strings.Contains(b.String(), "pam_unix.so") == true {
		return nil
	}
	return errors.New("Jeszcze nie wiem jak to sprecyzować xd")
}
func check_inactive_after_90(device *Device) error {
	/*
		IAM8-4: Inactive accounts are disabled within 90 days.
		https://konstruktoid.gitbooks.io/securing-ubuntu/content/sections/adduser/ensure_inactive_in_useradd.html
	*/

	config := &ssh.ClientConfig{
		User: device.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(device.Passwrd),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", device.Ip+":22", config)
	if err != nil {
		log.Fatal("Failed to dial: ", err.Error())
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	var b bytes.Buffer
	session.Stdout = &b
	if err := session.Run("grep '^INACTIVE=90$' /etc/default/useradd"); err != nil {
		return err
	}

	if strings.Contains(b.String(), "90") == false || strings.Contains(b.String(), "#") == true {
		return errors.New("Accounts are not disabled after 90 days of inactivity or")
	}

	return nil
}
func check_is_using_anti_malware(device *Device) error {
	/*
		//https://www.redhat.com/sysadmin/3-antimalware-solutions źródło
		PSW3-1: Protection against malicious code is deployed across the CIS in a multilayer approach.
		PSW3-2: Anti-malware diversity is used.
	*/
	config := &ssh.ClientConfig{
		User: device.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(device.Passwrd),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", device.Ip+":22", config)
	if err != nil {
		log.Fatal("Failed to dial: ", err.Error())
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	var b bytes.Buffer
	session.Stdout = &b

	if err := session.Run("dpkg -l | egrep -cE 'rkhunter |clamav |chkrootkit '"); err != nil {
		return err
	}

	val, err := strconv.ParseInt(b.String()[:len(b.String())-1], 10, 64)
	if err != nil {
		return err
	}
	if val == 0 {
		return errors.New("The instance doesn't use anti-malware")
	} else if val == 1 {
		return errors.New("A variety of anti-malware is not used")
	}
	return nil
}
func check_how_long_passwords_are_valid(device *Device) error {
	/*
		IAM4-4:Passwords are valid for between 1 to 3 years for CIS handling NC/NS/CTS information.
		IAM4-5:Passwords are valid for 1 to 2 years for CIS handling NU/NR information.
	*/
	config := &ssh.ClientConfig{
		User: device.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(device.Passwrd),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", device.Ip+":22", config)
	if err != nil {
		log.Fatal("Failed to dial: ", err.Error())
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	var b bytes.Buffer
	session.Stdout = &b
	if err := session.Run("grep '^PASS_MAX_DAYS' /etc/login.defs"); err != nil {
		return err
	}

	if strings.Contains(b.String(), "365") == false {
		return errors.New("Password expiration rule is not configured")
	}
	return nil
}
func check_logs_account(device *Device) error {
	/*
		IAM8-1:The CIS automatically logs account creation, modification, enabling; and privilege elevation, disabling and removal.


		https://www.loggly.com/ultimate-guide/linux-logging-basics/
		https://help.ubuntu.com/community/LinuxLogFiles
		"he Authorization Log tracks usage of authorization systems, the mechanisms for authorizing users
		which prompt for user passwords, such as the Pluggable Authentication Module (PAM) system, the sudo command, remote logins to sshd and so on"
	*/
	config := &ssh.ClientConfig{
		User: device.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(device.Passwrd),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", device.Ip+":22", config)
	if err != nil {
		log.Fatal("Failed to dial: ", err.Error())
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	var b bytes.Buffer
	session.Stdout = &b

	if err := session.Run("[[ -f /var/log/auth.log ]] && echo 'auth.log file exists'"); err != nil {
		return err
	}
	return nil
}

//PSW
func check_updates_anti_malware(device *Device) error {
	/*
		PSW3-4: Updates of the malware protection (e.g. signature definitions, heuristics) are deployed within 24 hours.
	*/
	config := &ssh.ClientConfig{
		User: device.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(device.Passwrd),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", device.Ip+":22", config)
	if err != nil {
		log.Fatal("Failed to dial: ", err.Error())
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	var b bytes.Buffer
	session.Stdout = &b
	if err := session.Run(" sudo grep '^Check' /etc/clamav/freshclam.conf ; dpkg -l | grep -o 'clamav-freshclam'"); err != nil {
		return err
	}
	updates_informations := strings.Split(b.String(), "\n")
	re := regexp.MustCompile("[0-9]+")
	daily_update := re.FindAllString(updates_informations[0], 10)[0]
	val, err := strconv.ParseInt(daily_update, 10, 64)
	if err != nil {
		return err
	}

	if val != 1 && updates_informations[1] != "clamav-freshclam" {
		return errors.New("the instance is not updated every 24 hours")
	}

	return nil
}

//POS
func check_hypervisor(device *Device) error {
	/*
		POS2-2: The use of a Type 2 hypervisor shall be approved by the SAA and is only permitted on a specialised CIS, for a specifically authorised purpose, and with use and access technically
		limited to specifically authorised personnel.
		Solution: Let's check type of hypervisor. If the hypervisor is type 1 then it does not need to be approved by SAA

		https://vapour-apps.com/what-is-hypervisor/
	*/

	type_2 := [7]string{"Oracle VM Server", "Parallels", "VMWare Player", "VMware Fusion", "VMware Workstation", "VMware Server", "VirtualBox"}
	config := &ssh.ClientConfig{
		User: device.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(device.Passwrd),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", device.Ip+":22", config)
	if err != nil {
		log.Fatal("Failed to dial: ", err.Error())
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	var b bytes.Buffer
	session.Stdout = &b
	if err := session.Run("sudo dmidecode | grep -i  -e 'Product Name:'"); err != nil {
		return err
	}
	for _, hypervisor_type := range type_2 {
		if strings.Contains(b.String(), hypervisor_type) == true {
			return errors.New("Instance is using Hypervisor type 2")
		}

	}
	return nil
}
func check_secure_email_gateway(device *Device) error {
	/*

		POS6-1: Email spam, phishing and malware protection is provided at entry and exit points to the CIS (e.g. by using a secure email gateway).

		https://howtoinstall.co/en/mailscanner
		MailScanner is a email gateway virus-scanner and spam and phishing-detector. It uses Exim, sendmail or postfix as its basis, and supports clamav
		 and some commercial virus scanning engines to do the actual virus scanning. For spam dectection MailScanner uses spamassassin. The action taken
		  on virus, spam or phishing mails can be configured with a flexible ruleset based on sender, receiver, scoring etc. Virus checking is disabled and spam checking is enabled by default.
	*/
	config := &ssh.ClientConfig{
		User: device.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(device.Passwrd),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", device.Ip+":22", config)
	if err != nil {
		log.Fatal("Failed to dial: ", err.Error())
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	var b bytes.Buffer
	session.Stdout = &b

	if err := session.Run("dpkg -l | grep -coE 'mailscanner'"); err != nil {
		return err
	}

	val, err := strconv.ParseInt(b.String()[:len(b.String())-1], 10, 64)
	if err != nil {
		return err
	}
	if val == 0 {
		return errors.New("Istnace is not using Message Content Filtering")
	}
	return nil
}

//CS
func check_removable_storage(device *Device) error {
	/*
		CS6-4: The use of unauthorized removable storage media on the control system is prevented.
		https://www.unixmen.com/block-access-usb-cddvd-debian-derivatives/
		https://www.kernel.org/doc/Documentation/usb/authorization.txt
		Z powodu że jest to instancja EC2 na amazonie to nie wszystkie pliki konfiguracyjne są dostępne w katalogu /sys/bus/usb/devices/DEVICE/aut zatem test ograniczam do wyłączenia urządzeń masowej pamięci usb
		i CD-ROM
	*/
	config := &ssh.ClientConfig{
		User: device.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(device.Passwrd),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", device.Ip+":22", config)
	if err != nil {
		log.Fatal("Failed to dial: ", err.Error())
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	var b bytes.Buffer
	session.Stdout = &b

	if err := session.Run("egrep -ce '^blacklist usb_storage' /etc/modprobe.d/blacklist.conf ; stat -c '%a' /media"); err != nil {
		return err
	}
	responds := strings.Split(b.String(), "\n")

	usb_information, err := strconv.ParseInt(responds[0], 10, 64)
	if err != nil {
		return err
	}

	cd_dvd_floppy_information, err := strconv.ParseInt(responds[1], 10, 64)
	if err != nil {
		return err
	}
	if usb_information != 1 || cd_dvd_floppy_information != 555 {
		return errors.New("Istance is able to use USB, CD, DVD, Floppy discs")
	}
	return nil
}

/*
	Run all tests
*/
func Check_all_rules(device *Device) (string, error) {

	err := check_weak_password(device)
	if err != nil {
		return "IAM4-1: the security rule is not met", err
	}
	err = check_blacklist_password(device)
	if err != nil {
		return "IAM4-2: the security rule is not met", err
	}
	err = check_10_generations_password(device)
	if err != nil {
		return "IAM4-6: the security rule is not met", err
	}
	err = check_hiden_auth(device)
	if err != nil {
		return "IAM3-6: the security rule is not met", err
	}
	err = check_hashed_password(device)
	if err != nil {
		return "IAM4-8: the security rule is not met", err
	}
	err = check_inactive_after_90(device)
	if err != nil {
		return "IAM8-4: the security rule is not met", err
	}
	err = check_is_using_anti_malware(device)
	if err != nil {
		return "PSW3-1 or PSW3-2: the security rule is not met", err
	}

	err = check_how_long_passwords_are_valid(device)
	if err != nil {
		return "IAM4-4 or IAM4-5: the security rule is not met", err
	}
	err = check_logs_account(device)

	if err != nil {
		return "IAM8-1: the security rule is not met", err
	}
	err = check_updates_anti_malware(device)

	if err != nil {
		return "PSW3-4: the security rule is not met", err
	}
	err = check_hypervisor(device)

	if err != nil {
		return "POS2-2: the security rule is not met", err
	}
	err = check_secure_email_gateway(device)
	if err != nil {
		return "POS6-1: the security rule is not met", err
	}
	err = check_removable_storage(device)
	if err != nil {
		return "CS6-4: the security rule is not met", err
	}
	return "", nil
}
