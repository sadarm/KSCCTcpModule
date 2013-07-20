#ifndef __KSCC_TCPMODULE_H__
#define __KSCC_TCPMODULE_H__

#include <cocos2d.h>

#define KSCCTCPMODULE_VERSION						0.1

#if (CC_TARGET_PLATFORM == CC_PLATFORM_WIN32)
 #pragma comment(lib, "ws2_32.lib")
 #pragma comment(lib, "pthreadVCE2.lib")
 #include <WinSock.h>
typedef SOCKET KSSocket;

#else
 #include <unistd.h>
 #include <arpa/inet.h>
 #include <sys/types.h>
 #include <sys/socket.h>
typedef int KSSocket;
#endif

#include <pthread.h>

//#include <openssl/rsa.h>
//#include <openssl/crypto.h>
//#include <openssl/x509.h>
//#include <openssl/pem.h>
//#include <openssl/ssl.h>
//#include <openssl/err.h>


// Notification Names
extern const char *KSCCTcpModuleNotificationDidConnect;
extern const char *KSCCTcpModuleNotificationDidDisConnect;
extern const char *KSCCTcpModuleNotificationReceivedData;
extern const char *KSCCTcpModuleNotificationDidFailConnection;


class KSCCTcpData : public cocos2d::CCObject
{
public:
    unsigned char *data;
	unsigned int length;
    
public:
    ~KSCCTcpData() { CC_SAFE_DELETE(data); }
	KSCCTcpData()
	: data(NULL)
	, length(0) {
    }
	KSCCTcpData(const KSCCTcpData &instance) {
		data = new unsigned char[instance.length];
		memcpy(data, instance.data, instance.length);
		length = instance.length;
	}
};



class KSCCTcpModule : public cocos2d::CCObject
{
public:
	typedef enum {
		ConnectionStatusSuccess = 0,
		ConnectionStatusFail,
		ConnectionStatusDisconnect,
		ConnectionStatusNone
	}ConnectionStatus;
    
    typedef enum {
        SecurityTypeNone,
        SecurityTypeSSL,
    }SecurityType;

private:
	KSSocket _sock;
	sockaddr_in _sockAddr;
	std::vector<char> _receiveData;

	ConnectionStatus _connStat;
    SecurityType _securityType;
    
//    SSL *_ssl;
//    SSL_METHOD *_ssl_method;
//    SSL_CTX *_ssl_ctx;
//    X509 *_cert;
    
    bool _ssl_done;

private:
	KSCCTcpModule();

	// Schedule
	void dispatchConnectCallbacks(float delta);
	void dispatchResponseCallbacks(float delta);

public:
	~KSCCTcpModule();
	KSSocket* getSocket() { return &_sock; }
	const sockaddr_in& getSocketAddr() { return _sockAddr; }
    
    bool initSSL();
    bool procSSL();

	void connect(const char *hostIp, const unsigned int &port);
	void close();

	void send(void *data, const unsigned int &len);
	void sendWithDataLength(void *data, const unsigned int &len);

	void setConnectionStatus(const ConnectionStatus &stat) {
		if(_connStat != stat) {
			_connStat = stat;
			cocos2d::CCLog("changed stat %d", (int)_connStat);
		}
	}
    
    void setSecurityType(const SecurityType &type) {
        if(_securityType != type) {
            _securityType = type;
        }
    }

	const ConnectionStatus& getConnectionStatus() { return _connStat; }
    const SecurityType& getSecurityType() { return _securityType; }
    bool isSSL_done() { return _ssl_done; }
	inline std::vector<char>* getReceiveData() { return &_receiveData; }
public:
	static KSCCTcpModule* getInstance();
};


#endif

