#include "KSCCTcpModule.h"
#include <queue>
extern std::vector<unsigned char> byteFromInt16(const int &param);
extern int int16FromByte(unsigned char *bytes);

std::vector<unsigned char> byteFromInt16(const int &param)
{
	std::vector<unsigned char> bytes(2);
	for (int i=1; i>-1; i--) {
		bytes[1-i] = (param >> (i * 8));
	}
	return bytes;
}

int int16FromByte(unsigned char *bytes)
{
	int intVal = 0;
	for (int i=0; i<2; i++) {
		intVal += (bytes[i] << ((1-i)*8));
	}

	return intVal;
}

extern void KSCCSleep(unsigned int milliSecond);
void KSCCSleep(unsigned int milliSecond) 
{
#if (CC_TARGET_PLATFORM == CC_PLATFORM_WIN32)
	Sleep(milliSecond);
#else
	usleep(milliSecond*1000);
#endif
}


#define BUFFER_SIZE 4096

#ifndef SOCKET_ERROR
// Win32
 #define SOCKET_ERROR            (-1)
 #define INVALID_SOCKET			(-1)	
#endif

USING_NS_CC;

const char *KSCCTcpModuleNotificationReceivedData = "KSCCTcpModuleNotificationReceivedData";
const char *KSCCTcpModuleNotificationDidConnect = "KSCCTcpModuleNotificationDidConnect";
const char *KSCCTcpModuleNotificationDidDisConnect = "KSCCTcpModuleNotificationDidDisConnect";
const char *KSCCTcpModuleNotificationDidFailConnection= "KSCCTcpModuleNotificationDidFailConnection";

#if (CC_TARGET_PLATFORM == CC_PLATFORM_WIN32)
typedef int int32_t;
#endif


// Threads
static pthread_t s_sendThread;
static pthread_t s_recvThread;

static pthread_cond_t s_sendCond = PTHREAD_COND_INITIALIZER;

// ThreadMutexes
static pthread_mutex_t	s_sendDataQueueMutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t  s_recvDataQueueMutex = PTHREAD_MUTEX_INITIALIZER;

// Queues
static std::queue<KSCCTcpData> s_recvDataQueue;
static std::queue<KSCCTcpData> s_sendDataQueue;

//static CCArray* s_recvDataQueue = NULL;
//static CCArray* s_sendDataQueue = NULL;

// Flags
static bool s_isSending = false;
static bool s_isRecving = false;

// ScheduleObjects
static CCObject *_connSchedule = NULL;
static CCObject *_responseSchedule = NULL;

// C Functions
bool static_create_socket(KSSocket *sock, const sockaddr_in &sockAddr);
void static_closeSocket(KSSocket *const sock);
int static_send(KSSocket *sock, const char *data, unsigned int len);
int static_receive(KSSocket *sock);

// call by thread
void* thread_send(void *arg);
void* thread_createSocket(void *arg);

static KSCCTcpModule *s_instance = NULL;

KSCCTcpModule* KSCCTcpModule::getInstance()
{
	if (NULL == s_instance) {
		s_instance = new KSCCTcpModule();
	}
	return s_instance;
}

KSCCTcpModule::~KSCCTcpModule()
{
//    delete _ssl;
}

KSCCTcpModule::KSCCTcpModule()
{       
	_connStat = ConnectionStatusNone;
    _securityType = SecurityTypeNone;
    _ssl_done = false;


	pthread_mutex_init(&s_sendDataQueueMutex, NULL);
	pthread_mutex_init(&s_recvDataQueueMutex, NULL);

	_connSchedule = new CCObject();
	_responseSchedule = new CCObject();

	CCDirector::sharedDirector()->getScheduler()->scheduleSelector(
		schedule_selector(KSCCTcpModule::dispatchConnectCallbacks), _connSchedule, 0, true);

	CCDirector::sharedDirector()->getScheduler()->scheduleSelector(
		schedule_selector(KSCCTcpModule::dispatchResponseCallbacks), _responseSchedule, 0, true);


	CCDirector::sharedDirector()->getScheduler()->pauseTarget(_connSchedule);
	CCDirector::sharedDirector()->getScheduler()->pauseTarget(_responseSchedule);
}

void KSCCTcpModule::dispatchConnectCallbacks(float delta)
{
    KSCCTcpModule *instance = KSCCTcpModule::getInstance();
	if(ConnectionStatusSuccess == instance->getConnectionStatus()) {
        // SecurityType is None or SSL Done
        if (SecurityTypeSSL == _securityType && !_ssl_done) {
            CCAssert(this->initSSL(), "SSL Failure");
        }
        CCDirector::sharedDirector()->getScheduler()->pauseTarget(_connSchedule);
        CCNotificationCenter::sharedNotificationCenter()->postNotification(KSCCTcpModuleNotificationDidConnect, NULL);
	} else if (ConnectionStatusFail == instance->getConnectionStatus()) {
        CCDirector::sharedDirector()->getScheduler()->pauseTarget(_connSchedule);
		CCNotificationCenter::sharedNotificationCenter()->postNotification(KSCCTcpModuleNotificationDidFailConnection, NULL);
	} else if (ConnectionStatusDisconnect == instance->getConnectionStatus()) {
        CCDirector::sharedDirector()->getScheduler()->pauseTarget(_connSchedule);
		CCNotificationCenter::sharedNotificationCenter()->postNotification(KSCCTcpModuleNotificationDidDisConnect, NULL);
	}
}

void KSCCTcpModule::dispatchResponseCallbacks(float delta)
{
    CCLog("KSCCTcpModule begin dispatchResponseCallbacks, recevDataQueue count: %d", s_recvDataQueue.size());
    CCDirector::sharedDirector()->getScheduler()->pauseTarget(_responseSchedule);
	pthread_mutex_lock(&s_recvDataQueueMutex);
	while (0 < s_recvDataQueue.size())
	{
		KSCCTcpData tcpData = s_recvDataQueue.front();
		CCNotificationCenter::sharedNotificationCenter()->postNotification(KSCCTcpModuleNotificationReceivedData, &tcpData);
		s_recvDataQueue.pop();
	}
	pthread_mutex_unlock(&s_recvDataQueueMutex);
    CCLog("KSCCTcpModule end dispatchResponseCallbacks");
}

bool KSCCTcpModule::initSSL()
{
    return true;
//    _ssl_method = SSLv3_client_method();
//    if ( !_ssl_method ) return false;
//    
//    _ssl_ctx = SSL_CTX_new(m_method);
//    if ( !_ssl_ctx ) return false;
//    
//    _ssl = SSL_new(m_ctx);
//    if ( !_ssl ) return false;
//
//    SSL_set_fd(_ssl, _sock);
}

bool KSCCTcpModule::procSSL()
{
//    int sslret = SSL_connect(_ssl);
//    
//    if (1 == sslret) {
//        _cert = SSL_get_peer_certificate(_ssl);
//        _ssl_done = true;
//        return true;
//    } else {
//        _ssl_done = false;
//    }
//    
//    switch(SSL_get_error(_ssl, sslret))
//    {
//        case SSL_ERROR_WANT_WRITE:
//        {
////            CCAssert(false, "want to write");
//            
//            break;
//        }
//        case SSL_ERROR_WANT_READ:
//        {
////            CCAssert(false, "want to read");
//            break;
//        }
//        default:
//        {
//            CCAssert(false, "failed handshake");
//            return false;
//        }
//    }
//    
    
    return true;
}

void KSCCTcpModule::connect(const char *hostIp, const unsigned int &port)
{
    sockaddr_in sockAddr;
    memset(&sockAddr, 0, sizeof(sockAddr));
    sockAddr.sin_family = AF_INET;
    sockAddr.sin_addr.s_addr = inet_addr(hostIp);
    sockAddr.sin_port = htons(port);
    _sockAddr = sockAddr;
    
    this->setConnectionStatus(KSCCTcpModule::ConnectionStatusNone);
    CCDirector::sharedDirector()->getScheduler()->resumeTarget(_connSchedule);

    int result = pthread_create(&s_recvThread, NULL, thread_createSocket, (void *)this);
    CCAssert(result >= 0, "failed creating socket");
    if (result >= 0) {
        pthread_detach(s_recvThread);
	} else {
		this->setConnectionStatus(KSCCTcpModule::ConnectionStatusFail);
		CCDirector::sharedDirector()->getScheduler()->resumeTarget(_connSchedule);
	}
    
    result = pthread_create(&s_sendThread, NULL, thread_send, (void *)this);
    CCAssert(result >= 0, "failed creating socket");
    if (result >= 0) {
        pthread_detach(s_sendThread);
	} else {
		this->setConnectionStatus(KSCCTcpModule::ConnectionStatusFail);
		CCDirector::sharedDirector()->getScheduler()->resumeTarget(_connSchedule);
	}
}

void KSCCTcpModule::close()
{
	static_closeSocket(&_sock);
}

void KSCCTcpModule::send(void *data, const unsigned int &len)
{
	CCLog("KSCCTcpModule begin Send");
	pthread_mutex_lock(&s_sendDataQueueMutex);
    KSCCTcpData tcpData;
	tcpData.data = new unsigned char[len];
	memcpy(tcpData.data, (unsigned char *)data, len);
	tcpData.length = len;
	s_sendDataQueue.push(tcpData);
	pthread_mutex_unlock(&s_sendDataQueueMutex);
    
    CCLog("KSCCTcpModule end Send");

	if(!s_isSending) {
		pthread_cond_signal(&s_sendCond);
	}
}

void KSCCTcpModule::sendWithDataLength(void *data, const unsigned int &len)
{
	CCLog("SendWithDataLength");
		std::vector<unsigned char> byteLen = byteFromInt16(len);
	int byteLenSize = byteLen.size();

	char *bytes = new char[len+byteLenSize];
	for (int i = 0; i < byteLenSize; i++)
	{
		bytes[i] = byteLen[i];
	}
	for (unsigned int i = 0; i < len; i++)
	{
		bytes[i + byteLenSize] = ((char *)data)[i];
	}

	this->send( (void *)bytes, len + byteLenSize);
}


#pragma mark - 
#pragma mark C Functions
bool static_create_socket(KSSocket *sock, const sockaddr_in &sockAddr)
{
    struct sockaddr_in server_addr = sockAddr;
    
#if (CC_TARGET_PLATFORM == CC_PLATFORM_WIN32)
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD( 2, 2 ),&wsaData) == SOCKET_ERROR)
	{
		CCLog( "WSAStartup configuresion failed.\n" );
		WSACleanup();
        return false;
	}
#endif
    
	if((*sock = socket(AF_INET,SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)
	{
		CCLog( "Socket open was failed.");
		static_closeSocket(sock);
        return false;
	}
	
	if(connect(*sock,(struct sockaddr *)(&server_addr), sizeof(server_addr)) == SOCKET_ERROR)
    {
        CCLog( "Socket connect was failed." );
		static_closeSocket(sock);
        return false;
    }
    
    CCLog("Created Socket: %d", *sock);
	CCLog("Success Server connecting" );
	return true;
}

void static_closeSocket(KSSocket *const sock)
{
#if (CC_TARGET_PLATFORM == CC_PLATFORM_WIN32)
    CCLog("close WinSocket: %d", *sock);

	if(NULL != sock) {
		closesocket(*sock);
	}
	WSACleanup();
#else
    CCLog("shutdown UnixSocket: %d", *sock);
//	close(*sock);
    shutdown(*sock, SHUT_RDWR);
#endif
}

int static_send(KSSocket *sock, const char *data, unsigned int len)
{
	int bytesCnt;
#if (CC_TARGET_PLATFORM == CC_PLATFORM_WIN32)
	bytesCnt = send(*sock, data, len, 0);
#else
	bytesCnt = send(*sock, data, len, 0);
#endif
	return bytesCnt;
}

int static_receive(KSSocket *sock)
{
    CCLog("static_receive");
	char buf[BUFFER_SIZE];
	int bytesCnt;
    
#if (CC_TARGET_PLATFORM == CC_PLATFORM_WIN32)
	bytesCnt = recv(*sock, buf, BUFFER_SIZE, 0);
#else
	bytesCnt = read(*sock, buf, BUFFER_SIZE);
#endif
    CCLog("receive byte cnt: %d", bytesCnt);

	if(0 < bytesCnt) {
		pthread_mutex_lock(&s_recvDataQueueMutex);
		KSCCTcpData data;
		data.data = new unsigned char[bytesCnt];
		memcpy(data.data, (unsigned char *)buf, bytesCnt);
		data.length = bytesCnt;
		s_recvDataQueue.push(data);
		pthread_mutex_unlock(&s_recvDataQueueMutex);
	}
	return bytesCnt;
}

// Thread Function
void* thread_send(void *arg)
{
	KSCCTcpModule *module = KSCCTcpModule::getInstance();
	while(true) {
		if (KSCCTcpModule::ConnectionStatusDisconnect == module->getConnectionStatus()) {
			pthread_exit(NULL);
			break;
		}
		if (0 == s_sendDataQueue.size())
		{
			s_isSending = false;
			pthread_mutex_lock(&s_sendDataQueueMutex);
			int rc = pthread_cond_wait(&s_sendCond, &s_sendDataQueueMutex);
			if (rc)
			{
				perror("mutext lock error "); 
				pthread_exit(NULL);
			}
			s_isSending = true;
		} else {
			pthread_mutex_lock(&s_sendDataQueueMutex);
		}

		KSCCTcpData tcpData = s_sendDataQueue.front();
		s_sendDataQueue.pop();

		pthread_mutex_unlock(&s_sendDataQueueMutex);
		
		int result = static_send(module->getSocket(), (const char *)tcpData.data, tcpData.length);
        
        if (module->getConnectionStatus() == KSCCTcpModule::ConnectionStatusDisconnect) {
			CCLog("fund: thread_send\ncan not send operation, because server connection be disconnected.");
            break;
        }
		if(0 > result && (module->getConnectionStatus() != KSCCTcpModule::ConnectionStatusDisconnect)) {
            s_isSending = false;
            CCLog("send failed");
            module->setConnectionStatus(KSCCTcpModule::ConnectionStatusDisconnect);
            CCDirector::sharedDirector()->getScheduler()->resumeTarget(_connSchedule);
			CCLog("Force disconnected");
			break;
        }
		//pthread_mutex_lock(&s_sendDataQueueMutex);
		//if (0 < s_sendDataQueue.size())
		//{
		//	s_sendDataQueue.pop();
		//}
		//pthread_mutex_unlock(&s_sendDataQueueMutex);
		
		KSCCSleep(100);
	}

	return NULL;
}


void* thread_createSocket(void *arg)
{
	KSCCTcpModule *module = KSCCTcpModule::getInstance();

	KSSocket *sock = module->getSocket();

	if(!static_create_socket(sock, module->getSocketAddr())) {
		module->setConnectionStatus(KSCCTcpModule::ConnectionStatusFail);
        CCLog("failed creating socket");
        return NULL;
    }

	module->setConnectionStatus(KSCCTcpModule::ConnectionStatusSuccess);

	while(true) {
		s_isRecving = true;
		int result = static_receive(sock);

        if (module->getConnectionStatus() == KSCCTcpModule::ConnectionStatusDisconnect) break;
        
		if(-1 == result && module->getConnectionStatus() != KSCCTcpModule::ConnectionStatusDisconnect) {
			CCDirector::sharedDirector()->getScheduler()->resumeTarget(_connSchedule);
			module->setConnectionStatus(KSCCTcpModule::ConnectionStatusDisconnect);
			CCLog("Force disconnected");
			break;
		} else if (0 == result && module->getConnectionStatus() != KSCCTcpModule::ConnectionStatusDisconnect) {
			CCDirector::sharedDirector()->getScheduler()->resumeTarget(_connSchedule);
			module->setConnectionStatus(KSCCTcpModule::ConnectionStatusDisconnect);
			CCLog("Disconnected");
			break;
		}
        CCLog("receive result code: %d", result);
		CCDirector::sharedDirector()->getScheduler()->resumeTarget(_responseSchedule);
		CCLog("receving...");
		s_isRecving = false;
	}
	return NULL;
}
