package ujcurl;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpHead;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.DnsResolver;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.util.EntityUtils;

import org.apache.http.HttpConnection;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.protocol.HttpContext;
import org.apache.http.HttpException;
import org.apache.http.conn.ManagedHttpClientConnection; // Needed for casting in interceptor (internal)

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.URI;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;

@Command(
    name = "ujcurl",
    mixinStandardHelpOptions = true,
    version = "ujcurl 1.0-SNAPSHOT",
    description = "Simulates curl-like HTTP requests with support for custom methods and headers."
)
public class ujCurl implements Callable<Integer> {

    // CONSTANT for HttpClientContext attribute key
    public static final String SSL_SESSION_ATTRIBUTE = "ssl-session";

    @Option(names = {"-v", "--verbose"}, description = "Enable verbose output.")
    private boolean verbose;

    @Option(names = "-I", description = "Fetch the headers only (HTTP HEAD request).")
    private boolean headRequest;

    @Option(names = "-i", description = "Include protocol response headers in the output.")
    private boolean includeHeaders;

    @Option(names = {"-k", "--insecure"}, description = "Allow insecure server connections when using SSL.")
    private boolean insecure;

    @Option(names = {"-f", "--fail"}, description = "Fail silently (exit 22) on HTTP errors (status >= 400).")
    private boolean fail;

    @Option(names = {"-X", "--request"},
            description = "HTTP method to use (e.g., GET, POST, PUT, DELETE, etc.). Defaults to GET.")
    private String requestMethod = "GET";

    @Option(names = {"-H", "--header"},
            description = "Custom header to pass to the server. Format: \"Header-Name: Header-Value\".")
    private List<String> headers = new ArrayList<>();

    @Parameters(index = "0", description = "The URL to request.")
    private String url;

    private static String connectHost = null;
    
    @Option(names = {"--connect-to"},
            description = "Remap a connection. Format: '::HOST' or 'HOST:PORT:IGNORED:IGNORED' (only HOST is used).")
    void setConnectTo(String value) {
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException("--connect-to argument cannot be empty.");
        }
        
        if (value.startsWith("::")) {
            connectHost = value.substring(2);
        } else {
            String[] parts = value.split(":");
            if (parts.length > 0) {
                connectHost = parts[0];
            }
        }

        if (connectHost == null || connectHost.isEmpty()) {
            throw new IllegalArgumentException("Could not parse host from --connect-to value.");
        }
    }

    @Override
    public Integer call() {
        try {
            final URI uri = new URI(url);
            final String originalHost = uri.getHost();
            final int originalPort = uri.getPort() == -1 ? (uri.getScheme().equalsIgnoreCase("https") ? 443 : 80) : uri.getScheme().equalsIgnoreCase("http") ? 80 : -1;

            if (verbose && "https".equalsIgnoreCase(uri.getScheme())) {
                displaySslInfo(); // Prints keystore/truststore config
            }

            final DnsResolver dnsResolver = new DnsResolver() {
                @Override
                public InetAddress[] resolve(final String host) throws UnknownHostException {
                    if (connectHost != null && host.equalsIgnoreCase(originalHost)) {
                        if (verbose) {
                            System.out.println("* Resolving '" + originalHost + "' to " + connectHost + " instead of DNS");
                        }
                        return InetAddress.getAllByName(connectHost);
                    }
                    return InetAddress.getAllByName(host);
                }
            };

            // --- Conditionally configure SSL based on -k flag ---
            SSLContext sslcontext;
            HostnameVerifier hostnameVerifier;
            if (insecure) {
                if (verbose) {
                    System.out.println("* WARNING: SSL certificate and hostname verification are disabled.");
                }
                SSLContext trustAllSslContext = SSLContext.getInstance("TLS");
                trustAllSslContext.init(null, new TrustManager[]{
                    new X509TrustManager() {
                        public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
                        public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                        public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                    }
                }, new SecureRandom());
                sslcontext = trustAllSslContext;
                hostnameVerifier = NoopHostnameVerifier.INSTANCE;
            } else {
                sslcontext = SSLContexts.createDefault();
                hostnameVerifier = SSLConnectionSocketFactory.getDefaultHostnameVerifier();
            }
            
            // USE CUSTOM SSLConnectionSocketFactory to capture SSLSession
            CustomSSLConnectionSocketFactory customSslSocketFactory = new CustomSSLConnectionSocketFactory(
                sslcontext, 
                hostnameVerifier
            );

            Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
                    .register("https", customSslSocketFactory) // Use the custom factory
                    .register("http", PlainConnectionSocketFactory.getSocketFactory())
                    .build();

            PoolingHttpClientConnectionManager cm = new PoolingHttpClientConnectionManager(
                socketFactoryRegistry, null, null, dnsResolver, -1, TimeUnit.MILLISECONDS
            );

            try (CloseableHttpClient httpClient = HttpClients.custom()
                    .setConnectionManager(cm)
                    .build()) { // SslSessionRecordingInterceptor is removed
                
                HttpClientContext context = HttpClientContext.create();
                HttpHost target = new HttpHost(originalHost, originalPort, uri.getScheme());

                if (verbose) {
                    System.out.println("*   Trying " + (connectHost != null ? connectHost : originalHost) + "...");
                    printConnectionInfo(connectHost != null ? connectHost : originalHost, originalPort);
                }
                
                HttpRequestBase httpRequest = createRequest(uri);
                
                for (String headerString : headers) {
                    if (headerString != null && headerString.contains(":")) {
                        String[] parts = headerString.split(":", 2);
                        if (parts.length == 2) {
                            httpRequest.setHeader(parts[0].trim(), parts[1].trim());
                        }
                    }
                }

                if (verbose) {
                    System.out.println("> " + httpRequest.getMethod() + " " + uri.getPath() + " HTTP/1.1");
                    for (org.apache.http.Header header : httpRequest.getAllHeaders()) {
                        System.out.println("> " + header.getName() + ": " + header.getValue());
                    }
                     System.out.println(">");
                }
                
                try (CloseableHttpResponse response = httpClient.execute(target, httpRequest, context)) {
                    // --- After execution, print SSL session details if verbose ---
                    if (verbose && "https".equalsIgnoreCase(uri.getScheme())) {
                        // Retrieve SSLSession from context attribute, set by CustomSSLConnectionSocketFactory
                        SSLSession sslSession = (SSLSession) context.getAttribute(SSL_SESSION_ATTRIBUTE);
                        if (sslSession != null) {
                            printSslSessionDetails(sslSession);
                        } else {
                            System.err.println("* No SSL session established or available in context for HTTPS connection (captured by factory).");
                        }
                    }

                    boolean printBody = !headRequest; 

                    if (verbose || headRequest || includeHeaders) {
                        System.out.println("HTTP/1.1 " + response.getStatusLine().getStatusCode() + " " + response.getStatusLine().getReasonPhrase());
                        for (org.apache.http.Header header : response.getAllHeaders()) {
                            System.out.println(header.getName() + ": " + header.getValue());
                        }
                        System.out.println();
                    }

                    if (fail && response.getStatusLine().getStatusCode() >= 400) {
                        System.err.println("curl: (22) The requested URL returned error: " + response.getStatusLine().getStatusCode());
                        return 22;
                    }

                    HttpEntity entity = response.getEntity();
                    if (printBody && entity != null) {
                        System.out.println(EntityUtils.toString(entity));
                    } else if (entity != null) {
                        EntityUtils.consume(entity);
                    }
                }
            }
            return 0;
        } catch (Exception e) {
            int code = exitCodeFor(e);
            String msg = e.getMessage();
            if (code == 60) msg = "SSL certificate problem: " + rootMessage(e);
            else if (code == 6) msg = "Could not resolve host: " + rootMessage(e);
            else if (code == 28) msg = "Operation timed out";
            else if (msg == null) msg = e.toString();
            System.err.println("curl: (" + code + ") " + msg);
            if (verbose) {
                e.printStackTrace(System.err);
            }
            return code;
        }
    }

    private static String rootMessage(Throwable e) {
        while (e.getCause() != null) e = e.getCause();
        return e.getMessage() != null ? e.getMessage() : e.toString();
    }

    // Maps failures to curl's exit codes (see "man curl", EXIT CODES).
    static int exitCodeFor(Throwable e) {
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (t instanceof java.security.cert.CertPathValidatorException
                    || t instanceof java.security.cert.CertificateException
                    || t instanceof javax.net.ssl.SSLPeerUnverifiedException) return 60;
            if (t instanceof UnknownHostException) return 6;
            if (t instanceof java.net.ConnectException) return 7;
            if (t instanceof java.net.SocketTimeoutException) return 28;
            if (t instanceof java.net.URISyntaxException) return 3;
        }
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (t instanceof javax.net.ssl.SSLException) return 35;
        }
        return 1;
    }
    
    // REMOVED: SslSessionRecordingInterceptor is no longer needed

    // NEW STATIC NESTED CLASS: CustomSSLConnectionSocketFactory to capture SSLSession
    static class CustomSSLConnectionSocketFactory extends SSLConnectionSocketFactory {
        public CustomSSLConnectionSocketFactory(final SSLContext sslContext, final HostnameVerifier hostnameVerifier) {
            super(sslContext, hostnameVerifier);
        }

        @Override
        public Socket createLayeredSocket(final Socket socket, final String target, int port, final HttpContext context) throws IOException {
            Socket sslSocket = super.createLayeredSocket(socket, target, port, context);
            if (sslSocket instanceof SSLSocket) {
                SSLSession session = ((SSLSocket) sslSocket).getSession();
                if (session != null && context instanceof HttpClientContext) {
                    ((HttpClientContext) context).setAttribute(SSL_SESSION_ATTRIBUTE, session);
                }
            }
            return sslSocket;
        }
    }


    private static void displaySslInfo() {
        System.out.println("--- SSL/TLS Configuration ---");
        String keyStorePath = System.getProperty("javax.net.ssl.keyStore");
        String keyStoreType = System.getProperty("javax.net.ssl.keyStoreType", "jks");
        String trustStorePath = System.getProperty("javax.net.ssl.trustStore");
        String trustStoreType = System.getProperty("javax.net.ssl.trustStoreType", "jks");

        System.out.println("Keystore: " + (keyStorePath != null ? keyStorePath : "Not explicitly set (using default system truststore)"));
        System.out.println("Keystore type: " + keyStoreType);
        System.out.println("Truststore: " + (trustStorePath != null ? trustStorePath : "Not explicitly set (using default system truststore)"));
        System.out.println("Truststore type: " + trustStoreType);

        try {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            KeyStore ks = null;
            if (trustStorePath != null) {
                ks = KeyStore.getInstance(trustStoreType);
                char[] password = System.getProperty("javax.net.ssl.trustStorePassword", "").toCharArray();
                try (InputStream is = new java.io.FileInputStream(trustStorePath)) {
                    ks.load(is, password);
                }
            }
            tmf.init(ks);

            for (TrustManager tm : tmf.getTrustManagers()) {
                if (tm instanceof X509TrustManager) {
                    System.out.println("Default Trust Manager: " + tm.getClass().getName());
                    break;
                }
            }
        } catch (KeyStoreException | NoSuchAlgorithmException | IOException | CertificateException e) {
            System.err.println("Could not fully inspect default trust manager: " + e.getMessage());
        }
        System.out.println("----------------------------");
    }

    private void printConnectionInfo(String host, int port) {
        try {
            InetAddress inetAddress = InetAddress.getByName(host);
            String ipAddress = inetAddress.getHostAddress();
            System.out.println("*   Connecting to " + host + " (" + ipAddress + ") port " + port);
        } catch (IOException e) {
            System.err.println("*   Could not resolve IP address for " + host + ": " + e.getMessage());
            System.out.println("*   Connecting to " + host + " port " + port);
        }
    }

    private HttpRequestBase createRequest(URI uri) {
        if (headRequest) {
            return new HttpHead(uri);
        }

        switch (requestMethod.toUpperCase()) {
            case "POST":
                return new HttpPost(uri);
            case "PUT":
                return new HttpPut(uri);
            case "DELETE":
                return new HttpDelete(uri);
            case "HEAD":
                return new HttpHead(uri);
            case "GET":
            default:
                return new HttpGet(uri);
        }
    }
    
    private void printSslSessionDetails(SSLSession session) {
        if (session == null) {
            System.out.println("* No SSL session information available.");
            return;
        }

        try {
            String protocol = session.getProtocol();
            String cipherSuite = session.getCipherSuite();
            System.out.println("* SSL connection using " + protocol + " / " + cipherSuite);
            
            System.out.println("* ALPN: server accepted h2 (placeholder, not easily available from SSLSession)");

            java.security.cert.Certificate[] peerCerts = session.getPeerCertificates();
            if (peerCerts != null && peerCerts.length > 0) {
                System.out.println("* Server certificate:");
                X509Certificate serverCert = (X509Certificate) peerCerts[0];
                
                System.out.println("*  subject: " + serverCert.getSubjectX500Principal().getName());
                SimpleDateFormat sdf = new SimpleDateFormat("MMM dd HH:mm:ss yyyy 'GMT'");
                System.out.println("*  start date: " + sdf.format(serverCert.getNotBefore()));
                System.out.println("*  expire date: " + sdf.format(serverCert.getNotAfter()));
                
                try {
                    Collection<List<?>> sans = serverCert.getSubjectAlternativeNames();
                    if (sans != null) {
                        for (List<?> san : sans) {
                            if (san != null && san.size() >= 2) {
                                System.out.println("*  subjectAltName: host \"" + san.get(1) + "\" matched cert's \"" + san.get(1) + "\"");
                            }
                        }
                    }
                } catch (Exception e) {
                    System.err.println("*  Could not parse Subject Alternative Names: " + e.getMessage());
                }
                
                System.out.println("*  issuer: " + serverCert.getIssuerX500Principal().getName());
                System.out.println("* SSL certificate verify ok."); 

                for (int i = 0; i < peerCerts.length; i++) {
                    X509Certificate cert = (X509Certificate) peerCerts[i];
                    System.out.println("*   Certificate level " + i + ": Public key type " + cert.getPublicKey().getAlgorithm() + ", signed using " + cert.getSigAlgName());
                }
            } else {
                System.out.println("* Server certificate: Not available.");
            }
        } catch (Exception e) {
            System.err.println("* Error retrieving SSL details from session: " + e.getMessage());
            if (verbose) e.printStackTrace(System.err);
        }
    }

    private static CloseableHttpClient buildHttpClient() {
        return null;
    }

    public static void main(String[] args) {
        System.exit(new CommandLine(new ujCurl()).execute(args));
    }
}