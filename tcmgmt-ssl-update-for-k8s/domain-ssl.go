package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/tencentcloud/tencentcloud-sdk-go-intl-en/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go-intl-en/tencentcloud/common/profile"
	live "github.com/tencentcloud/tencentcloud-sdk-go-intl-en/tencentcloud/live/v20180801"
	ssl "github.com/tencentcloud/tencentcloud-sdk-go-intl-en/tencentcloud/ssl/v20191205"
)

type Account struct {
	Name string
	ID   string
	Key  string
}

type EnvConfig struct {
	Schedule string            `json:"schedule"`
	Accounts []map[string]string `json:"accounts"`
}

var logger *log.Logger

// ====== logger ======
func initLogger() {
	// 檢查 logs 資料夾是否存在，若無則建立
	logDir := "logs"
	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		os.MkdirAll(logDir, 0755)
	}

	// 開啟日誌檔案，用於寫入
	logFile := filepath.Join(logDir, "tcmgmt-ssl-update.log")
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		// 如果無法開啟日誌檔案，則直接終止程式
		log.Fatalf("無法開啟日誌檔案: %v", err)
	}

	// 創建一個多重寫入器，將日誌同時寫入檔案和標準輸出 (os.Stdout)
	mw := io.MultiWriter(os.Stdout, f)
	logger = log.New(mw, "", log.LstdFlags)
}

func logInfo(v ...interface{}) {
	logger.Println(v...)
}

func logError(v ...interface{}) {
	logger.Println("❌", fmt.Sprint(v...))
}

// ====== env.json 帳號處理 ======
func loadAccounts() []Account {
	data, err := os.ReadFile("env.json")
	if err != nil {
		logError("無法讀取 env.json:", err)
		os.Exit(1)
	}

	var cfg EnvConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		logError("解析 env.json 失敗:", err)
		os.Exit(1)
	}

	var accounts []Account
	for _, m := range cfg.Accounts {
		var name, id, key string
		for k, v := range m {
			switch {
			case strings.HasSuffix(k, "_id"):
				name = strings.TrimSuffix(k, "_id")
				id = decryptExternal(v)
			case k == "id":
				name = "default"
				id = decryptExternal(v)
			case strings.HasSuffix(k, "_key"):
				key = decryptExternal(v)
			case k == "key":
				key = decryptExternal(v)
			}
		}
		if id != "" && key != "" {
			accounts = append(accounts, Account{Name: name, ID: id, Key: key})
		} else {
			logInfo("⚠️ 忽略一個無效帳號:", m)
		}
	}
	return accounts
}

func decryptExternal(cipher string) string {
	if len(cipher) > 8 && cipher[:8] == "{cipher}" {
		cmd := exec.Command("./decrypt", cipher)
		out, err := cmd.Output()
		if err != nil {
			logError("解密失敗:", err)
			os.Exit(1)
		}
		return strings.TrimSpace(string(out))
	}
	return cipher
}

// ====== 主流程 ======
func main() {
	initLogger()
	logInfo("🚀 Job 憑證檢查流程開始")

	accounts := loadAccounts()
	if len(accounts) == 0 {
		logInfo("找不到可用的帳號，結束程式。")
		os.Exit(0)
	}
	logInfo(fmt.Sprintf("✅ 成功載入 %d 個帳號", len(accounts)))

	for _, acc := range accounts {
		logInfo("=======================================")
		logInfo(fmt.Sprintf("🔑 開始處理帳號: %s", acc.Name))

		cred := common.NewCredential(acc.ID, acc.Key)

		liveCpf := profile.NewClientProfile()
		liveCpf.HttpProfile.Endpoint = "live.intl.tencentcloudapi.com"
		liveClient, err := live.NewClient(cred, "", liveCpf)
		if err != nil {
			logError(fmt.Sprintf("建立 Live client 失敗: %v", err))
			continue
		}

		sslCpf := profile.NewClientProfile()
		sslCpf.HttpProfile.Endpoint = "ssl.intl.tencentcloudapi.com"
		sslClient, err := ssl.NewClient(cred, "", sslCpf)
		if err != nil {
			logError(fmt.Sprintf("建立 SSL client 失敗: %v", err))
			continue
		}

		describeResp, err := liveClient.DescribeLiveDomains(live.NewDescribeLiveDomainsRequest())
		if err != nil {
			logError(fmt.Sprintf("DescribeLiveDomains 失敗: %v", err))
			continue
		}

		if describeResp.Response == nil || len(describeResp.Response.DomainList) == 0 {
			logInfo("找不到任何直播域名。")
			continue
		}

		logInfo(fmt.Sprintf("✅ 找到 %d 個直播域名。", len(describeResp.Response.DomainList)))

		for _, d := range describeResp.Response.DomainList {
			if d.Type == nil || *d.Type != 1 {
				continue
			}
			domain := *d.Name
			logInfo("---------------------------------------")
			logInfo(fmt.Sprintf("🌐 處理域名: %s", domain))

			certBaseDir := getCertBaseDir(domain)
			localCertPath := filepath.Join("/app/certs", certBaseDir, "tls.crt")
			localKeyPath := filepath.Join("/app/certs", certBaseDir, "tls.key")

			if _, err := os.Stat(localCertPath); os.IsNotExist(err) {
				logInfo(fmt.Sprintf("本地憑證文件不存在，跳過此域名: %s", localCertPath))
				continue
			}
			if _, err := os.Stat(localKeyPath); os.IsNotExist(err) {
				logInfo(fmt.Sprintf("本地金鑰文件不存在，跳過此域名: %s", localKeyPath))
				continue
			}

			req := live.NewDescribeLiveDomainCertBindingsRequest()
			req.DomainSearch = common.StringPtr(domain)
			respCert, err := liveClient.DescribeLiveDomainCertBindings(req)
			if err != nil {
				logError(fmt.Sprintf("DescribeLiveDomainCertBindings 失敗: %v", err))
				continue
			}

			liveCertDaysLeft := 0
			oldCertId := ""
			if len(respCert.Response.LiveDomainCertBindings) > 0 {
				binding := respCert.Response.LiveDomainCertBindings[0]
				oldCertId = *binding.CloudCertId
				expireTime, _ := time.Parse("2006-01-02 15:04:05", *binding.CertExpireTime)
				liveCertDaysLeft = int(time.Until(expireTime).Hours() / 24)
				logInfo(fmt.Sprintf("Live 憑證到期日: %s, 剩餘 %d 天", *binding.CertExpireTime, liveCertDaysLeft))
			} else {
				logInfo("此域名尚未綁定憑證。")
			}

			localDaysLeft := getLocalCertDaysLeft(localCertPath)
			logInfo(fmt.Sprintf("本地憑證剩餘 %d 天", localDaysLeft))

			if liveCertDaysLeft < 30 && localDaysLeft > 31 {
				logInfo("💡 條件符合，將上傳新憑證並替換。")
				certId := uploadSSL(sslClient, domain, localCertPath, localKeyPath)
				if certId != "" {
					bindSSLCert(liveClient, domain, certId)
					if oldCertId != "" {
						deleteSSL(sslClient, oldCertId)
					}
				}
			} else {
				logInfo("✅ 條件不符，不需上傳新憑證。")
			}
		}
	}
	logInfo("=======================================")
	logInfo("🏁 Job 憑證檢查流程結束")
}

// ====== 工具函式 ======
func getLocalCertDaysLeft(certPath string) int {
	data, err := os.ReadFile(certPath)
	if err != nil {
		logError(fmt.Sprintf("讀取本地憑證文件 %s 失敗: %v", certPath, err))
		return 0
	}
	block, _ := pem.Decode(data)
	if block == nil {
		logError(fmt.Sprintf("解析本地憑證文件 %s 失敗: 無效的 PEM 區塊", certPath))
		return 0
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		logError(fmt.Sprintf("解析 X.509 憑證失敗: %v", err))
		return 0
	}
	return int(time.Until(cert.NotAfter).Hours() / 24)
}

func uploadSSL(client *ssl.Client, domain, certPath, keyPath string) string {
	certData, err := os.ReadFile(certPath)
	if err != nil {
		logError(fmt.Sprintf("讀取憑證文件 %s 失敗: %v", certPath, err))
		return ""
	}
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		logError(fmt.Sprintf("讀取金鑰文件 %s 失敗: %v", keyPath, err))
		return ""
	}

	req := ssl.NewUploadCertificateRequest()
	req.CertificatePublicKey = common.StringPtr(string(certData))
	req.CertificatePrivateKey = common.StringPtr(string(keyData))
	req.Alias = common.StringPtr(domain)

	resp, err := client.UploadCertificate(req)
	if err != nil {
		logError(fmt.Sprintf("UploadCertificate 失敗: %v", err))
		return ""
	}
	if resp.Response.CertificateId != nil {
		logInfo(fmt.Sprintf("✅ 憑證上傳成功，新憑證 ID: %s", *resp.Response.CertificateId))
		return *resp.Response.CertificateId
	}
	return ""
}

func bindSSLCert(client *live.Client, domain, certId string) {
	req := live.NewModifyLiveDomainCertBindingsRequest()
	req.DomainInfos = []*live.LiveCertDomainInfo{
		{DomainName: common.StringPtr(domain), Status: common.Int64Ptr(1)},
	}
	req.CloudCertId = common.StringPtr(certId)

	_, err := client.ModifyLiveDomainCertBindings(req)
	if err != nil {
		logError(fmt.Sprintf("ModifyLiveDomainCertBindings 失敗: %v", err))
		return
	}
	logInfo(fmt.Sprintf("✅ ModifyLiveDomainCertBindings 成功，已將新憑證綁定至域名 %s。", domain))
}

func deleteSSL(client *ssl.Client, certId string) {
	req := ssl.NewDeleteCertificateRequest()
	req.CertificateId = common.StringPtr(certId)

	_, err := client.DeleteCertificate(req)
	if err != nil {
		logError(fmt.Sprintf("DeleteCertificate 失敗: %v", err))
		return
	}
	logInfo(fmt.Sprintf("✅ DeleteCertificate 成功，已刪除舊憑證 ID: %s。", certId))
}

// getCertBaseDir 從完整域名中取得根網域作為憑證資料夾名稱
func getCertBaseDir(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "." + parts[len(parts)-1]
	}
	return domain
}
