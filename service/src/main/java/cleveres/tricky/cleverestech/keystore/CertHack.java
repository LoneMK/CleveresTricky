package cleveres.tricky.cleverestech.keystore;

import android.content.pm.PackageManager;
import android.hardware.security.keymint.Algorithm;
import android.hardware.security.keymint.EcCurve;
import android.hardware.security.keymint.KeyParameter;
import android.hardware.security.keymint.KeyPurpose;
import android.hardware.security.keymint.Tag;
import android.security.keystore.KeyProperties;
import android.system.keystore2.KeyDescriptor;
import android.util.Pair;

import androidx.annotation.Nullable;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import javax.security.auth.x500.X500Principal;

import cleveres.tricky.cleverestech.Config;
import cleveres.tricky.cleverestech.Logger;
import cleveres.tricky.cleverestech.UtilKt;
import cleveres.tricky.cleverestech.util.CborEncoder;
import cleveres.tricky.cleverestech.util.FastByteArrayOutputStream;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class CertHack {
    private static final ASN1ObjectIdentifier OID = new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17");
    
    // RKP additions
    private static final String RKP_MAC_KEY_ALGORITHM = "HmacSHA256";
    // LOCAL_HMAC_KEY removed - obtained from LocalRkpProxy
    private static final ThreadLocal<MessageDigest> SHA256_DIGEST = new ThreadLocal<MessageDigest>() {
        @Override
        protected MessageDigest initialValue() {
            try {
                return MessageDigest.getInstance("SHA-256");
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    };



    private static final int ATTESTATION_APPLICATION_ID_PACKAGE_INFOS_INDEX = 0;
    private static final int ATTESTATION_APPLICATION_ID_SIGNATURE_DIGESTS_INDEX = 1;
    private static final int ATTESTATION_PACKAGE_INFO_PACKAGE_NAME_INDEX = 0;

    private static final CertificateFactory certificateFactory;

    private static class State {
        final Map<String, List<KeyBox>> keyboxes;
        final Map<String, List<KeyBox>> keyboxFiles;
        final Map<CacheKey, Certificate[]> certificateCache;

        State(Map<String, List<KeyBox>> keyboxes, Map<String, List<KeyBox>> keyboxFiles) {
            this.keyboxes = keyboxes;
            this.keyboxFiles = keyboxFiles;
            this.certificateCache = Collections.synchronizedMap(new HashMap<>());
        }
    }

    private static volatile State state = new State(Collections.emptyMap(), Collections.emptyMap());
    private static final Map<String, AtomicInteger> rotationCounters = new ConcurrentHashMap<>();

    static {
        rotationCounters.put(KeyProperties.KEY_ALGORITHM_EC, new AtomicInteger(0));
        rotationCounters.put(KeyProperties.KEY_ALGORITHM_RSA, new AtomicInteger(0));
        // Register BouncyCastle once at class init to avoid race conditions
        // when multiple threads concurrently call removeProvider/addProvider.
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        Security.addProvider(new BouncyCastleProvider());
        try {
            certificateFactory = CertificateFactory.getInstance("X.509");
        } catch (Throwable t) {
            Logger.e("", t);
            throw new RuntimeException(t);
        }
    }

    private static final int ATTESTATION_PACKAGE_INFO_VERSION_INDEX = 1;

    public static boolean canHack() {
        return !state.keyboxes.isEmpty();
    }

    public static int getKeyboxCount() {
        int count = 0;
        for (List<KeyBox> list : state.keyboxes.values()) {
            count += list.size();
        }
        return count;
    }

    private static PEMKeyPair parseKeyPair(String key) throws Throwable {
        try (PEMParser parser = new PEMParser(new StringReader(UtilKt.trimLine(key)))) {
            return (PEMKeyPair) parser.readObject();
        }
    }

    private static Certificate parseCert(String cert) throws Throwable {
        try (PemReader reader = new PemReader(new StringReader(UtilKt.trimLine(cert)))) {
            return certificateFactory.generateCertificate(new ByteArrayInputStream(reader.readPemObject().getContent()));
        }
    }

    private static byte[] getByteArrayFromAsn1(ASN1Encodable asn1Encodable) throws CertificateParsingException {
        if (!(asn1Encodable instanceof DEROctetString derOctectString)) {
            throw new CertificateParsingException("Expected DEROctetString");
        }
        return derOctectString.getOctets();
    }

    /**
     * Optimization: Use a custom key object to avoid expensive Base64 encoding
     * and large String allocations for cache lookups.
     * This saves ~33% memory per key and avoids O(N) encoding overhead.
     */
    private static final class CacheKey {
        private final byte[] leafEncoded;
        private final int patchLevel;
        private final int hashCode;

        public CacheKey(byte[] leafEncoded, int patchLevel) {
            this.leafEncoded = leafEncoded;
            this.patchLevel = patchLevel;
            this.hashCode = 31 * Arrays.hashCode(leafEncoded) + patchLevel;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            CacheKey cacheKey = (CacheKey) o;
            return patchLevel == cacheKey.patchLevel && Arrays.equals(leafEncoded, cacheKey.leafEncoded);
        }

        @Override
        public int hashCode() {
            return hashCode;
        }
    }

    public static List<KeyBox> parseKeyboxXml(Reader reader) {
        return parseKeyboxXml(reader, "unknown.xml");
    }

    public static List<KeyBox> parseKeyboxXml(Reader reader, String filename) {
        if (reader == null) return Collections.emptyList();
        List<KeyBox> parsedList = new ArrayList<>();
        try {
            XMLParser xmlParser = new XMLParser(reader);
            XMLParser.Element root = xmlParser.getRoot();

            if (root == null || !"AndroidAttestation".equals(root.name)) {
                return Collections.emptyList();
            }

            XMLParser.Element numKeyboxes = root.getChild("NumberOfKeyboxes");
            if (numKeyboxes == null || numKeyboxes.getText() == null) {
                return Collections.emptyList();
            }

            List<XMLParser.Element> keyboxes = root.getChildren("Keybox");

            for (XMLParser.Element keybox : keyboxes) {
                List<XMLParser.Element> keys = keybox.getChildren("Key");
                for (XMLParser.Element key : keys) {
                    // keyboxAlgorithm is fetched but seemingly unused in original code, kept for consistency if side effects existed (unlikely)
                    String keyboxAlgorithm = key.attributes.get("algorithm");

                    XMLParser.Element privateKeyElement = key.getChild("PrivateKey");
                    String privateKey = privateKeyElement != null ? privateKeyElement.getText() : null;
                    if (privateKey == null) continue;

                    XMLParser.Element certChain = key.getChild("CertificateChain");
                    if (certChain == null) continue;

                    XMLParser.Element numCertsElement = certChain.getChild("NumberOfCertificates");
                    if (numCertsElement == null || numCertsElement.getText() == null) continue;

                    int numberOfCertificates = Integer.parseInt(Objects.requireNonNull(numCertsElement.getText()));

                    List<XMLParser.Element> certificates = certChain.getChildren("Certificate");
                    if (certificates.size() < numberOfCertificates) {
                        Logger.e("Keybox XML declares " + numberOfCertificates + " certificates but only " + certificates.size() + " found, skipping");
                        continue;
                    }
                    LinkedList<Certificate> certificateChain = new LinkedList<>();
                    for (int j = 0; j < numberOfCertificates; j++) {
                        String certPem = certificates.get(j).getText();
                        certificateChain.add(parseCert(certPem));
                    }

                    // Verify keys
                    var pemKp = parseKeyPair(privateKey);
                    var kp = new JcaPEMKeyConverter().getKeyPair(pemKp);
                    parsedList.add(new KeyBox(kp, certificateChain, filename));
                }
            }
            return parsedList;
        } catch (Throwable t) {
            Logger.e("Error parsing xml: " + t.getClass().getName());
        }
        return Collections.emptyList();
    }

    public static void setKeyboxes(List<KeyBox> boxes) {
        if (boxes == null || boxes.isEmpty()) {
            Logger.i("clear all keyboxes");
            state = new State(Collections.emptyMap(), Collections.emptyMap());
            return;
        }

        Map<String, List<KeyBox>> newKeyboxes = new HashMap<>();
        Map<String, List<KeyBox>> newKeyboxFiles = new HashMap<>();

        for (KeyBox box : boxes) {
            String algo = box.keyPair.getPublic().getAlgorithm();
            if ("ECDSA".equalsIgnoreCase(algo) || "EC".equalsIgnoreCase(algo)) {
                algo = KeyProperties.KEY_ALGORITHM_EC;
            } else {
                algo = KeyProperties.KEY_ALGORITHM_RSA;
            }
            newKeyboxes.computeIfAbsent(algo, k -> new ArrayList<>()).add(box);
            newKeyboxFiles.computeIfAbsent(box.filename, k -> new ArrayList<>()).add(box);
        }

        int ecCount = newKeyboxes.getOrDefault(KeyProperties.KEY_ALGORITHM_EC, Collections.emptyList()).size();
        int rsaCount = newKeyboxes.getOrDefault(KeyProperties.KEY_ALGORITHM_RSA, Collections.emptyList()).size();
        Logger.i("update keyboxes: total=" + boxes.size() + " (EC=" + ecCount + ", RSA=" + rsaCount + ")");

        state = new State(newKeyboxes, newKeyboxFiles);
    }

    public static void readFromXml(Reader reader) {
        if (reader == null) {
            setKeyboxes(Collections.emptyList());
            return;
        }
        setKeyboxes(parseKeyboxXml(reader));
    }

    /**
     * Optimization: Checks if the certificate chain for the given leaf and UID is already cached.
     * This allows avoiding expensive certificate parsing if we have a cache hit.
     */
    public static Certificate[] getCachedCertificateChain(byte[] leafEncoded, int uid) {
        if (leafEncoded == null) return null;
        try {
            State currentState = state;
            int patchLevel = Config.INSTANCE.getPatchLevel(uid);
            CacheKey cacheKey = new CacheKey(leafEncoded, patchLevel);
            // Thread-safe map, no synchronization needed for get
            return currentState.certificateCache.get(cacheKey);
        } catch (Throwable t) {
            Logger.e("Exception in getCachedCertificateChain", t);
        }
        return null;
    }

    public static Certificate[] hackCertificateChain(Certificate[] caList, int uid) {
        if (caList == null) throw new UnsupportedOperationException("caList is null!");
        try {
            State currentState = state;
            byte[] leafEncoded = caList[0].getEncoded();
            int patchLevel = Config.INSTANCE.getPatchLevel(uid);
            CacheKey cacheKey = new CacheKey(leafEncoded, patchLevel);

            Map<CacheKey, Certificate[]> cache = currentState.certificateCache;
            synchronized (cache) {
                 if (cache.containsKey(cacheKey)) {
                     // Logger.d("Cache hit for uid=" + uid);
                     return cache.get(cacheKey);
                 }
            }

            // Optimization: Avoid redundant parsing if already X509Certificate
            X509Certificate leaf;
            if (caList[0] instanceof X509Certificate) {
                leaf = (X509Certificate) caList[0];
            } else {
                leaf = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(leafEncoded));
            }

            byte[] bytes = leaf.getExtensionValue(OID.getId());
            if (bytes == null) return caList;

            // Optimization: Use original encoded bytes to avoid copy/re-encoding
            X509CertificateHolder leafHolder = new X509CertificateHolder(leafEncoded);
            Extension ext = leafHolder.getExtension(OID);
            if (ext == null || ext.getExtnValue() == null) {
                Logger.e("Attestation extension present but holder returned null — skipping hack");
                return caList;
            }
            ASN1Sequence sequence = ASN1Sequence.getInstance(ext.getExtnValue().getOctets());
            ASN1Encodable[] encodables = sequence.toArray();
            ASN1Sequence teeEnforced = (ASN1Sequence) encodables[7];

            // List to collect all tags for sorting
            List<ASN1TaggedObject> allTags = new ArrayList<>();
            ASN1Encodable rootOfTrust = null;
            byte[] moduleHash = Config.INSTANCE.getModuleHash();

            // Check for ID Attestation overrides
            Map<Integer, byte[]> idAttestationTags = new HashMap<>();
            String[] tags = {"BRAND", "DEVICE", "PRODUCT", "SERIAL", "IMEI", "MEID", "MANUFACTURER", "MODEL"};
            int[] tagIds = {710, 711, 712, 713, 714, 715, 716, 717};
            boolean hasIdAttestation = false;

            for (int i = 0; i < tags.length; i++) {
                byte[] val = Config.INSTANCE.getAttestationId(tags[i], uid);
                if (val != null) {
                    idAttestationTags.put(tagIds[i], val);
                    hasIdAttestation = true;
                }
            }

            for (ASN1Encodable asn1Encodable : teeEnforced) {
                // Skip non-tagged elements gracefully: some OEM implementations may inject
                // unexpected element types. Silently skipping is safer than crashing the
                // entire attestation chain for one malformed element.
                if (!(asn1Encodable instanceof ASN1TaggedObject taggedObject)) {
                    Logger.e("Unexpected ASN1 element type in TEE enforced: " + asn1Encodable.getClass().getName());
                    continue;
                }
                int tag = taggedObject.getTagNo();
                if (tag == 704) {
                    rootOfTrust = taggedObject.getBaseObject().toASN1Primitive();
                    continue;
                }
                // Filter 724 (ModuleHash) and 706 (OS Patch Level)
                if (tag == 724 || tag == 706) {
                    continue;
                }
                // Filter ID Attestation tags ONLY if we are overriding THAT specific tag
                // If hasIdAttestation is true but idAttestationTags doesn't have this tag, we KEEP it (Patch strategy)
                if (hasIdAttestation && idAttestationTags.containsKey(tag)) {
                    continue;
                }
                allTags.add(taggedObject);
            }

            // Add spoofed patch level
            allTags.add(new DERTaggedObject(true, 706, new ASN1Integer(patchLevel)));

            // Add spoofed ID Attestation tags
            if (hasIdAttestation) {
                for (Map.Entry<Integer, byte[]> entry : idAttestationTags.entrySet()) {
                    allTags.add(new DERTaggedObject(true, entry.getKey(), new DEROctetString(entry.getValue())));
                }
            }

            if (moduleHash != null) {
                allTags.add(new DERTaggedObject(true, 724, new DEROctetString(moduleHash)));
            }

            LinkedList<Certificate> certificates;
            X509v3CertificateBuilder builder;
            ContentSigner signer;

            String leafAlgo = leaf.getPublicKey().getAlgorithm();
            // Normalize algorithm name: JCA may return "ECDSA" instead of "EC"
            if ("ECDSA".equalsIgnoreCase(leafAlgo) || "EC".equalsIgnoreCase(leafAlgo)) {
                leafAlgo = KeyProperties.KEY_ALGORITHM_EC;
            } else {
                leafAlgo = KeyProperties.KEY_ALGORITHM_RSA;
            }

            // App-specific keybox selection
            List<KeyBox> list = null;
            var appConfig = Config.INSTANCE.getAppConfig(uid);
            if (appConfig != null && appConfig.getKeyboxFilename() != null) {
                list = currentState.keyboxFiles.get(appConfig.getKeyboxFilename());
                if (list == null || list.isEmpty()) {
                    Logger.e("App requested keybox " + appConfig.getKeyboxFilename() + " but it's not loaded/valid.");
                }
            }

            if (list == null || list.isEmpty()) {
                list = currentState.keyboxes.get(leafAlgo);
            }

            if (list == null || list.isEmpty())
                throw new UnsupportedOperationException("unsupported algorithm " + leafAlgo);

            int idx = (rotationCounters.get(leafAlgo).getAndIncrement() & 0x7FFFFFFF) % list.size();
            var k = list.get(idx);

            certificates = new LinkedList<>(k.certificates);
            if (certificates.isEmpty()) {
                throw new UnsupportedOperationException("Keybox has no certificates for algorithm " + leafAlgo);
            }
            builder = new X509v3CertificateBuilder(
                    new X509CertificateHolder(
                            certificates.get(0).getEncoded()
                    ).getSubject(),
                    leafHolder.getSerialNumber(),
                    leafHolder.getNotBefore(),
                    leafHolder.getNotAfter(),
                    leafHolder.getSubject(),
                    leafHolder.getSubjectPublicKeyInfo()
            );
            signer = new JcaContentSignerBuilder(leaf.getSigAlgName())
                    .build(k.keyPair.getPrivate());

            byte[] verifiedBootKey = UtilKt.getBootKey();
            if (verifiedBootKey == null) {
                Logger.e("getBootKey() returned null, generating random 32-byte key");
                verifiedBootKey = new byte[32];
                new java.security.SecureRandom().nextBytes(verifiedBootKey);
            }
            byte[] verifiedBootHash = null;
            try {
                if (rootOfTrust == null || !(rootOfTrust instanceof ASN1Sequence r)) {
                    throw new CertificateParsingException("Expected sequence for root of trust, found "
                            + (rootOfTrust == null ? "null" : rootOfTrust.getClass().getName()));
                }
                verifiedBootHash = getByteArrayFromAsn1(r.getObjectAt(3));
            } catch (Throwable t) {
                Logger.e("failed to get verified boot key or hash from original, use randomly generated instead", t);
            }

            if (verifiedBootHash == null) {
                verifiedBootHash = UtilKt.getBootHash();
            }

            ASN1Encodable[] rootOfTrustEnc = {
                    new DEROctetString(verifiedBootKey),
                    ASN1Boolean.TRUE,
                    new ASN1Enumerated(0),
                    new DEROctetString(verifiedBootHash)
            };

            ASN1Sequence hackedRootOfTrust = new DERSequence(rootOfTrustEnc);
            ASN1TaggedObject rootOfTrustTagObj = new DERTaggedObject(704, hackedRootOfTrust);
            allTags.add(rootOfTrustTagObj);

            // Sort tags by tag number to ensure ASN.1 compliance (and correct order for injection)
            Collections.sort(allTags, (a, b) -> Integer.compare(a.getTagNo(), b.getTagNo()));

            ASN1EncodableVector vector = new ASN1EncodableVector();
            for(ASN1TaggedObject t : allTags) vector.add(t);

            ASN1Sequence hackEnforced = new DERSequence(vector);
            encodables[7] = hackEnforced;
            ASN1Sequence hackedSeq = new DERSequence(encodables);

            ASN1OctetString hackedSeqOctets = new DEROctetString(hackedSeq);
            Extension hackedExt = new Extension(OID, false, hackedSeqOctets);
            // builder.addExtension(hackedExt); // Replaced by in-place loop below

            for (ASN1ObjectIdentifier extensionOID : leafHolder.getExtensions().getExtensionOIDs()) {
                if (OID.getId().equals(extensionOID.getId())) {
                     builder.addExtension(hackedExt);
                } else {
                     builder.addExtension(leafHolder.getExtension(extensionOID));
                }
            }
            certificates.addFirst(new JcaX509CertificateConverter().getCertificate(builder.build(signer)));

            Certificate[] result = certificates.toArray(new Certificate[0]);
            synchronized (cache) {
                cache.put(cacheKey, result);
            }
            return result;

        } catch (Throwable t) {
            Logger.e("Exception in hackCertificateChain", t);
        }
        return caList;
    }

    public static Pair<KeyPair, List<Certificate>> generateKeyPair(int uid, KeyDescriptor descriptor, KeyGenParameters params) {
        return generateKeyPair(uid, descriptor, params, null, null);
    }

    public static Pair<KeyPair, List<Certificate>> generateKeyPair(int uid, KeyDescriptor descriptor, KeyGenParameters params,
                                                                   @Nullable KeyPair issuerKeyPair, @Nullable List<Certificate> issuerChain) {
        Logger.i("Requested KeyPair with alias: " + descriptor.alias);
        KeyPair rootKP;
        X500Name issuer;
        int size = params.keySize;
        KeyPair kp = null;
        KeyBox keyBox = null;
        try {
            State currentState = state;
            var algo = params.algorithm;
            String keyAlgo = null;

            if (algo == Algorithm.EC) {
                Logger.d("GENERATING EC KEYPAIR OF SIZE " + size);
                kp = buildECKeyPair(params);
                keyAlgo = KeyProperties.KEY_ALGORITHM_EC;
            } else if (algo == Algorithm.RSA) {
                Logger.d("GENERATING RSA KEYPAIR OF SIZE " + size);
                kp = buildRSAKeyPair(params);
                keyAlgo = KeyProperties.KEY_ALGORITHM_RSA;
            }

            if (keyAlgo != null) {
                // App specific check
                var appConfig = Config.INSTANCE.getAppConfig(uid);
                List<KeyBox> list = null;
                if (appConfig != null && appConfig.getKeyboxFilename() != null) {
                     list = currentState.keyboxFiles.get(appConfig.getKeyboxFilename());
                }
                if (list == null || list.isEmpty()) {
                     list = currentState.keyboxes.get(keyAlgo);
                }

                if (list != null && !list.isEmpty()) {
                    int idx = (rotationCounters.get(keyAlgo).getAndIncrement() & 0x7FFFFFFF) % list.size();
                    keyBox = list.get(idx);
                }
            }

            if (keyBox == null) {
                Logger.e("UNSUPPORTED ALGORITHM or NO KEYBOX: " + algo);
                return null;
            }

            // Permission guards: Device ID attestation tags require caller permission checks
            boolean hasIdPermission = true; // Placeholder for actual permission check, typically checkCallingPermission(READ_PRIVILEGED_PHONE_STATE)
            if (!hasIdPermission) {
                params.imei = null;
                params.meid = null;
                params.serial = null;
            }

            // Inject ID attestation overrides
            byte[] brand = Config.INSTANCE.getAttestationId("BRAND", uid);
            if (brand != null) params.brand = brand;
            byte[] device = Config.INSTANCE.getAttestationId("DEVICE", uid);
            if (device != null) params.device = device;
            byte[] product = Config.INSTANCE.getAttestationId("PRODUCT", uid);
            if (product != null) params.product = product;
            byte[] manufacturer = Config.INSTANCE.getAttestationId("MANUFACTURER", uid);
            if (manufacturer != null) params.manufacturer = manufacturer;
            byte[] model = Config.INSTANCE.getAttestationId("MODEL", uid);
            if (model != null) params.model = model;
            byte[] serial = Config.INSTANCE.getAttestationId("SERIAL", uid);
            if (serial != null) params.serial = serial;
            byte[] imei = Config.INSTANCE.getAttestationId("IMEI", uid);
            if (imei != null) params.imei = imei;
            byte[] meid = Config.INSTANCE.getAttestationId("MEID", uid);
            if (meid != null) params.meid = meid;

            List<Certificate> signingChain;
            if (issuerKeyPair != null && issuerChain != null && !issuerChain.isEmpty()) {
                rootKP = issuerKeyPair;
                signingChain = issuerChain;
            } else {
                rootKP = keyBox.keyPair;
                signingChain = keyBox.certificates;
            }

            issuer = new X509CertificateHolder(
                    signingChain.get(0).getEncoded()
            ).getSubject();

            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuer,
                    params.certificateSerial,
                    params.certificateNotBefore,
                    params.certificateNotAfter,
                    params.certificateSubject,
                    kp.getPublic()
            );

            KeyUsage keyUsage = new KeyUsage(KeyUsage.keyCertSign);
            certBuilder.addExtension(Extension.keyUsage, true, keyUsage);
            Extension attestExt = createExtension(params, uid);
            if (attestExt == null) {
                Logger.e("createExtension returned null for uid=" + uid + " alias=" + descriptor.alias);
                return null;
            }
            certBuilder.addExtension(attestExt);

            ContentSigner contentSigner;
            String signingAlgo = rootKP.getPrivate().getAlgorithm();
            if ("EC".equalsIgnoreCase(signingAlgo) || "ECDSA".equalsIgnoreCase(signingAlgo)) {
                contentSigner = new JcaContentSignerBuilder("SHA256withECDSA").build(rootKP.getPrivate());
            } else {
                contentSigner = new JcaContentSignerBuilder("SHA256withRSA").build(rootKP.getPrivate());
            }
            X509CertificateHolder certHolder = certBuilder.build(contentSigner);
            var leaf = new JcaX509CertificateConverter().getCertificate(certHolder);
            List<Certificate> chain = new ArrayList<>(signingChain);
            chain.add(0, leaf);
            Logger.d("Successfully generated X500 Cert for alias: " + descriptor.alias);
            return new Pair<>(kp, chain);
        } catch (Throwable t) {
            Logger.e("", t);
        }
        return null;
    }

    private static KeyPair buildECKeyPair(KeyGenParameters params) throws Exception {
        // Provider already registered in static init — no remove/add needed

        String algo = "ECDSA";
        String curveName = params.ecCurveName;

        if (params.ecCurve == EcCurve.CURVE_25519) {
            if (params.purpose.contains(KeyPurpose.SIGN) || params.purpose.contains(KeyPurpose.ATTEST_KEY)) {
                algo = "Ed25519";
                curveName = "Ed25519";
            } else {
                algo = "XDH";
                curveName = "X25519";
            }
        }

        ECGenParameterSpec spec = new ECGenParameterSpec(curveName);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algo, BouncyCastleProvider.PROVIDER_NAME);
        kpg.initialize(spec);
        return kpg.generateKeyPair();
    }

    private static KeyPair buildRSAKeyPair(KeyGenParameters params) throws Exception {
        // Provider already registered in static init — no remove/add needed
        RSAKeyGenParameterSpec spec = new RSAKeyGenParameterSpec(
                params.keySize, params.rsaPublicExponent);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        kpg.initialize(spec);
        return kpg.generateKeyPair();
    }

    private static ASN1Encodable[] fromIntList(List<Integer> list) {
        ASN1Encodable[] result = new ASN1Encodable[list.size()];
        for (int i = 0; i < list.size(); i++) {
            result[i] = new ASN1Integer(list.get(i));
        }
        return result;
    }

    private static Extension createExtension(KeyGenParameters params, int uid) {
        try {
            byte[] key = UtilKt.getBootKey();
            byte[] hash = UtilKt.getBootHash();
            // Guard against null boot key/hash (BUG 2) — generate random fallback
            if (key == null) {
                key = new byte[32];
                new java.security.SecureRandom().nextBytes(key);
            }
            if (hash == null) {
                hash = new byte[32];
                new java.security.SecureRandom().nextBytes(hash);
            }

            ASN1Encodable[] rootOfTrustEncodables = {new DEROctetString(key), ASN1Boolean.TRUE,
                    new ASN1Enumerated(0), new DEROctetString(hash)};

            ASN1Sequence rootOfTrustSeq = new DERSequence(rootOfTrustEncodables);

            var Apurpose = new DERSet(fromIntList(params.purpose));
            var Aalgorithm = new ASN1Integer(params.algorithm);
            var AkeySize = new ASN1Integer(params.keySize);
            var Adigest = new DERSet(fromIntList(params.digest));
            var AecCurve = new ASN1Integer(params.ecCurve);
            var AnoAuthRequired = DERNull.INSTANCE;

            // To be loaded
            var AosVersion = new ASN1Integer(UtilKt.getOsVersion());
            var AosPatchLevel = new ASN1Integer(Config.INSTANCE.getPatchLevel(uid));

            var AapplicationID = createApplicationId(uid);
            var AbootPatchlevel = new ASN1Integer(UtilKt.getPatchLevelLong());
            var AvendorPatchLevel = new ASN1Integer(UtilKt.getPatchLevelLong());

            var AcreationDateTime = new ASN1Integer(System.currentTimeMillis());
            var Aorigin = new ASN1Integer(0);

            var purpose = new DERTaggedObject(true, 1, Apurpose);
            var algorithm = new DERTaggedObject(true, 2, Aalgorithm);
            var keySize = new DERTaggedObject(true, 3, AkeySize);
            var digest = new DERTaggedObject(true, 5, Adigest);
            var ecCurve = new DERTaggedObject(true, 10, AecCurve);
            var noAuthRequired = new DERTaggedObject(true, 503, AnoAuthRequired);
            var creationDateTime = new DERTaggedObject(true, 701, AcreationDateTime);
            var origin = new DERTaggedObject(true, 702, Aorigin);
            var rootOfTrust = new DERTaggedObject(true, 704, rootOfTrustSeq);
            var osVersion = new DERTaggedObject(true, 705, AosVersion);
            var osPatchLevel = new DERTaggedObject(true, 706, AosPatchLevel);
            var applicationID = new DERTaggedObject(true, 709, AapplicationID);
            var vendorPatchLevel = new DERTaggedObject(true, 718, AvendorPatchLevel);
            var bootPatchLevel = new DERTaggedObject(true, 719, AbootPatchlevel);

            List<ASN1Encodable> teeEnforcedList = new ArrayList<>(Arrays.asList(
                    purpose, algorithm, keySize, digest, ecCurve,
                    noAuthRequired, origin, rootOfTrust, osVersion, osPatchLevel, vendorPatchLevel,
                    bootPatchLevel
            ));

            // Support device properties attestation — guard each field individually
            // to prevent NPE when only some fields are set (BUG 3)
            if (params.brand != null) {
                teeEnforcedList.add(new DERTaggedObject(true, 710, new DEROctetString(params.brand)));
            }
            if (params.device != null) {
                teeEnforcedList.add(new DERTaggedObject(true, 711, new DEROctetString(params.device)));
            }
            if (params.product != null) {
                teeEnforcedList.add(new DERTaggedObject(true, 712, new DEROctetString(params.product)));
            }
            if (params.manufacturer != null) {
                teeEnforcedList.add(new DERTaggedObject(true, 716, new DEROctetString(params.manufacturer)));
            }
            if (params.model != null) {
                teeEnforcedList.add(new DERTaggedObject(true, 717, new DEROctetString(params.model)));
            }

            if (params.serial != null) {
                teeEnforcedList.add(new DERTaggedObject(true, 713, new DEROctetString(params.serial)));
            }
            if (params.imei != null) {
                teeEnforcedList.add(new DERTaggedObject(true, 714, new DEROctetString(params.imei)));
            }
            if (params.meid != null) {
                teeEnforcedList.add(new DERTaggedObject(true, 715, new DEROctetString(params.meid)));
            }

            byte[] moduleHash = Config.INSTANCE.getModuleHash();
            if (moduleHash != null) {
                teeEnforcedList.add(new DERTaggedObject(true, 724, new DEROctetString(moduleHash)));
            }

            teeEnforcedList.sort((a, b) -> {
                int tagA = ((ASN1TaggedObject) a).getTagNo();
                int tagB = ((ASN1TaggedObject) b).getTagNo();
                return Integer.compare(tagA, tagB);
            });

            ASN1Encodable[] teeEnforcedEncodables = teeEnforcedList.toArray(new ASN1Encodable[0]);

            ASN1Encodable[] softwareEnforced = {applicationID, creationDateTime};

            ASN1OctetString keyDescriptionOctetStr = getAsn1OctetString(teeEnforcedEncodables, softwareEnforced, params);

            return new Extension(new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"), false, keyDescriptionOctetStr);
        } catch (Throwable t) {
            Logger.e("", t);
        }
        return null;
    }

    private static ASN1OctetString getAsn1OctetString(ASN1Encodable[] teeEnforcedEncodables, ASN1Encodable[] softwareEnforcedEncodables, KeyGenParameters params) throws IOException {
        int attestVer = 100;
        String attestVerStr = Config.INSTANCE.getBuildVar("ATTESTATION_VERSION");
        if (attestVerStr != null && !attestVerStr.isEmpty()) {
            try {
                attestVer = Integer.parseInt(attestVerStr);
            } catch (Exception ignored) {
            }
        }

        int keyMintVer = UtilKt.getKeyMintVersion();
        String keyMintVerStr = Config.INSTANCE.getBuildVar("KEYMINT_VERSION");
        if (keyMintVerStr != null && !keyMintVerStr.isEmpty()) {
            try {
                keyMintVer = Integer.parseInt(keyMintVerStr);
            } catch (Exception ignored) {
            }
        }

        ASN1Integer attestationVersion = new ASN1Integer(attestVer);
        ASN1Enumerated attestationSecurityLevel = new ASN1Enumerated(1);
        ASN1Integer keymasterVersion = new ASN1Integer(keyMintVer);
        ASN1Enumerated keymasterSecurityLevel = new ASN1Enumerated(1);
        ASN1OctetString attestationChallenge = new DEROctetString(params.attestationChallenge);
        ASN1OctetString uniqueId = new DEROctetString("".getBytes());
        ASN1Encodable softwareEnforced = new DERSequence(softwareEnforcedEncodables);
        ASN1Sequence teeEnforced = new DERSequence(teeEnforcedEncodables);

        ASN1Encodable[] keyDescriptionEncodables = {attestationVersion, attestationSecurityLevel, keymasterVersion,
                keymasterSecurityLevel, attestationChallenge, uniqueId, softwareEnforced, teeEnforced};

        ASN1Sequence keyDescriptionHackSeq = new DERSequence(keyDescriptionEncodables);

        return new DEROctetString(keyDescriptionHackSeq);
    }

    @SuppressWarnings("deprecation")
    private static DEROctetString createApplicationId(int uid) throws Throwable {
        var pm = Config.INSTANCE.getPm();
        if (pm == null) {
            throw new IllegalStateException("createApplicationId: pm not found!");
        }
        // Use Config's package cache to avoid redundant IPC calls to PackageManager
        var packages = Config.INSTANCE.getPackages(uid);
        var size = packages.length;
        ASN1Encodable[] packageInfoAA = new ASN1Encodable[size];
        Set<Digest> signatures = new HashSet<>();
        var dg = SHA256_DIGEST.get();
        dg.reset();
        for (int i = 0; i < size; i++) {
            var name = packages[i];
            var info = UtilKt.getPackageInfoCompat(pm, name, PackageManager.GET_SIGNATURES, uid / 100000);
            ASN1Encodable[] arr = new ASN1Encodable[2];
            arr[ATTESTATION_PACKAGE_INFO_PACKAGE_NAME_INDEX] =
                    new DEROctetString(packages[i].getBytes(StandardCharsets.UTF_8));
            arr[ATTESTATION_PACKAGE_INFO_VERSION_INDEX] = new ASN1Integer(info.getLongVersionCode());
            packageInfoAA[i] = new DERSequence(arr);
            for (var s : info.signatures) {
                signatures.add(new Digest(dg.digest(s.toByteArray())));
            }
        }

        ASN1Encodable[] signaturesAA = new ASN1Encodable[signatures.size()];
        var i = 0;
        for (var d : signatures) {
            signaturesAA[i] = new DEROctetString(d.digest);
            i++;
        }

        ASN1Encodable[] applicationIdAA = new ASN1Encodable[2];
        applicationIdAA[ATTESTATION_APPLICATION_ID_PACKAGE_INFOS_INDEX] =
                new DERSet(packageInfoAA);
        applicationIdAA[ATTESTATION_APPLICATION_ID_SIGNATURE_DIGESTS_INDEX] =
                new DERSet(signaturesAA);

        return new DEROctetString(new DERSequence(applicationIdAA).getEncoded());
    }

    record Digest(byte[] digest) {
        @Override
        public boolean equals(@Nullable Object o) {
            if (o instanceof Digest d)
                return Arrays.equals(digest, d.digest);
            return false;
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(digest);
        }
    }

    public record KeyBox(KeyPair keyPair, List<Certificate> certificates, String filename) {
    }

    public static class KeyGenParameters {
        public int keySize;
        public int algorithm;
        public BigInteger certificateSerial;
        public Date certificateNotBefore;
        public Date certificateNotAfter;
        public X500Name certificateSubject;

        public BigInteger rsaPublicExponent;
        public int ecCurve;
        public String ecCurveName;

        public boolean isNoAuthRequired = false;

        public List<Integer> purpose = new ArrayList<>();
        public List<Integer> digest = new ArrayList<>();
        public List<Integer> blockMode = new ArrayList<>();
        public List<Integer> padding = new ArrayList<>();
        public List<Integer> mgfDigest = new ArrayList<>();

        public byte[] attestationChallenge;
        public byte[] brand;
        public byte[] device;
        public byte[] product;
        public byte[] manufacturer;
        public byte[] model;
        public byte[] serial;
        public byte[] imei;
        public byte[] meid;

        public KeyGenParameters(KeyParameter[] params) {
            for (var kp : params) {
                var p = kp.value;
                switch (kp.tag) {
                    case Tag.KEY_SIZE -> keySize = p.getInteger();
                    case Tag.ALGORITHM -> algorithm = p.getAlgorithm();
                    case Tag.CERTIFICATE_SERIAL -> certificateSerial = new BigInteger(p.getBlob());
                    case Tag.CERTIFICATE_NOT_BEFORE ->
                            certificateNotBefore = new Date(p.getDateTime());
                    case Tag.CERTIFICATE_NOT_AFTER ->
                            certificateNotAfter = new Date(p.getDateTime());
                    case Tag.CERTIFICATE_SUBJECT ->
                            certificateSubject = new X500Name(new X500Principal(p.getBlob()).getName());
                    case Tag.RSA_PUBLIC_EXPONENT -> rsaPublicExponent = new BigInteger(p.getBlob());
                    case Tag.EC_CURVE -> {
                        ecCurve = p.getEcCurve();
                        ecCurveName = getEcCurveName(ecCurve);
                    }
                    case Tag.NO_AUTH_REQUIRED -> isNoAuthRequired = true;
                    case Tag.PURPOSE -> {
                        purpose.add(p.getKeyPurpose());
                    }
                    case Tag.DIGEST -> {
                        digest.add(p.getDigest());
                    }
                    case Tag.BLOCK_MODE -> blockMode.add(p.getBlockMode());
                    case Tag.PADDING -> padding.add(p.getPaddingMode());
                    case Tag.RSA_OAEP_MGF_DIGEST -> mgfDigest.add(p.getDigest());
                    case Tag.ATTESTATION_CHALLENGE -> attestationChallenge = p.getBlob();
                    case Tag.ATTESTATION_ID_BRAND -> brand = p.getBlob();
                    case Tag.ATTESTATION_ID_DEVICE -> device = p.getBlob();
                    case Tag.ATTESTATION_ID_PRODUCT -> product = p.getBlob();
                    case Tag.ATTESTATION_ID_MANUFACTURER -> manufacturer = p.getBlob();
                    case Tag.ATTESTATION_ID_MODEL -> model = p.getBlob();
                    case Tag.ATTESTATION_ID_SERIAL -> serial = p.getBlob();
                    case Tag.ATTESTATION_ID_IMEI -> imei = p.getBlob();
                    case Tag.ATTESTATION_ID_MEID -> meid = p.getBlob();
                }
            }
        }

        private static String getEcCurveName(int curve) {
            String res;
            switch (curve) {
                case EcCurve.CURVE_25519 -> res = "X25519";
                case EcCurve.P_224 -> res = "secp224r1";
                case EcCurve.P_256 -> res = "secp256r1";
                case EcCurve.P_384 -> res = "secp384r1";
                case EcCurve.P_521 -> res = "secp521r1";
                default -> throw new IllegalArgumentException("unknown curve");
            }
            return res;
        }
    }

    // ============ RKP support ============



    /**
     * Creates a fully compliant COSE_Key structure for EC P-256.
     * RFC 8152:
     * kty (1) : EC2 (2)
     * alg (3) : ES256 (-7)
     * crv (-1): P-256 (1)
     * x (-2)  : bstr
     * y (-3)  : bstr
     */
    private static Map<Object, Object> createCoseKeyMap(KeyPair keyPair) {
        // P-256 Public Key (Uncompressed) format: 0x04 + 32-byte X + 32-byte Y
        byte[] encoded = keyPair.getPublic().getEncoded();
        // The getEncoded() returns SubjectPublicKeyInfo (ASN.1), not raw point.
        // We need to extract the raw key bytes. 
        // For P-256, SPKI header is typically 26/27 bytes. The last 65 bytes are the key (0x04 + X + Y).
        
        byte[] x = new byte[32];
        byte[] y = new byte[32];
        
        if (encoded.length > 64) {
             // Heuristic: Extract last 64 bytes (X || Y)
             // This works for standard Java generic providers (SunEC etc)
             int start = encoded.length - 64;
             System.arraycopy(encoded, start, x, 0, 32);
             System.arraycopy(encoded, start + 32, y, 0, 32);
        } else {
             // Should not happen for valid P-256 keys
             Logger.e("Invalid P-256 key length: " + encoded.length);
             return null;
        }

        Map<Object, Object> coseKey = new HashMap<>();
        coseKey.put(1, 2);   // kty: EC2
        coseKey.put(3, -7);  // alg: ES256
        coseKey.put(-1, 1);  // crv: P-256
        coseKey.put(-2, x);  // x coord
        coseKey.put(-3, y);  // y coord
        
        return coseKey;
    }

    public static byte[] generateMacedPublicKey(KeyPair keyPair, byte[] hmacKey) {
        if (keyPair == null || hmacKey == null) return null;
        try {
            // 1. Protected Header
            // { 1 (alg) : 5 (HMAC 256/256) }
            Map<Integer, Object> protectedMap = new HashMap<>();
            protectedMap.put(1, 5);
            byte[] protectedHeader = CborEncoder.encode(protectedMap);
            
            // 2. Payload (COSE_Key)
            Map<Object, Object> coseKey = createCoseKeyMap(keyPair);
            if (coseKey == null) return null;
            byte[] payload = CborEncoder.encode(coseKey);
            
            // 3. MAC Calculation (MAC_structure)
            // [ "MAC0", protected, external_aad, payload ]
            List<Object> macStructure = new ArrayList<>();
            macStructure.add("MAC0");
            macStructure.add(protectedHeader);
            macStructure.add(new byte[0]); // external_aad
            macStructure.add(payload);
            
            byte[] toBeMaced = CborEncoder.encode(macStructure);
            
            Mac hmac = Mac.getInstance(RKP_MAC_KEY_ALGORITHM);
            hmac.init(new SecretKeySpec(hmacKey, RKP_MAC_KEY_ALGORITHM));
            byte[] tag = hmac.doFinal(toBeMaced);
            
            // 4. Final COSE_Mac0 [ protected, unprotected, payload, tag ]
            List<Object> coseMac0 = new ArrayList<>();
            coseMac0.add(protectedHeader);
            coseMac0.add(new HashMap<>()); // unprotected
            coseMac0.add(payload);
            coseMac0.add(tag);
            
            return CborEncoder.encode(coseMac0);
            
        } catch (Throwable t) {
            Logger.e("Failed to generate MacedPublicKey", t);
            return null;
        }
    }

    /**
     * Builds the certificate request response matching Android RKP AuthenticatedRequest v2 spec.
     *
     * AuthenticatedRequest = [version: 1, UdsCerts, DiceCertChain, SignedData]
     * SignedData = COSE_Sign1 over Sig_structure containing CsrPayload
     * CsrPayload = [version: 3, CertificateType, DeviceInfo, KeysToSign]
     */
    public static byte[] createCertificateRequestResponse(
            java.util.List<byte[]> publicKeys,
            byte[] challenge,
            byte[] deviceInfoBody
    ) {
        try {
            java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("EC");
            kpg.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
            java.security.KeyPair signingKey = kpg.generateKeyPair();

            // === CsrPayload: [version: 3, CertificateType, DeviceInfo, KeysToSign] ===
            FastByteArrayOutputStream csrPayloadStream = new FastByteArrayOutputStream(2048);
            csrPayloadStream.write(0x84); // Array(4)
            CborEncoder.encodeItem(csrPayloadStream, 3); // version
            CborEncoder.encodeItem(csrPayloadStream, "keymint"); // CertificateType
            csrPayloadStream.write(deviceInfoBody); // DeviceInfo (already CBOR-encoded map)
            // KeysToSign: extract COSE_Key from each MacedPublicKey (payload field)
            int keyCount = publicKeys.size();
            if (keyCount < 24) csrPayloadStream.write(0x80 | keyCount);
            else if (keyCount <= 0xFF) { csrPayloadStream.write(0x98); csrPayloadStream.write(keyCount); }
            else { csrPayloadStream.write(0x99); csrPayloadStream.write(keyCount >> 8); csrPayloadStream.write(keyCount); }
            for (byte[] macedKey : publicKeys) {
                csrPayloadStream.write(macedKey);
            }
            byte[] csrPayload = csrPayloadStream.toByteArray();

            // === SignedData: COSE_Sign1 [protected, unprotected, payload, signature] ===
            Map<Integer, Object> signProtected = new HashMap<>();
            signProtected.put(1, -7); // alg: ES256
            byte[] signProtectedBytes = CborEncoder.encode(signProtected);

            // payload = bstr .cbor [challenge, CsrPayload]
            FastByteArrayOutputStream payloadStream = new FastByteArrayOutputStream(2048);
            payloadStream.write(0x82); // Array(2)
            CborEncoder.encodeItem(payloadStream, challenge);
            payloadStream.write(csrPayload);
            byte[] signedPayload = payloadStream.toByteArray();

            // Sig_structure = ["Signature1", signProtectedBytes, externalAad, signedPayload]
            List<Object> sigStructure = new ArrayList<>();
            sigStructure.add("Signature1");
            sigStructure.add(signProtectedBytes);
            sigStructure.add(new byte[0]); // external_aad
            sigStructure.add(signedPayload);
            byte[] toBeSigned = CborEncoder.encode(sigStructure);

            java.security.Signature signer = java.security.Signature.getInstance("SHA256withECDSA");
            signer.initSign(signingKey.getPrivate());
            signer.update(toBeSigned);
            byte[] signature = signer.sign();

            // COSE_Sign1 = [signProtectedBytes, {}, signedPayload, signature]
            FastByteArrayOutputStream signedDataStream = new FastByteArrayOutputStream(4096);
            signedDataStream.write(0x84); // Array(4)
            CborEncoder.encodeItem(signedDataStream, signProtectedBytes);
            signedDataStream.write(0xA0); // empty map {}
            CborEncoder.encodeItem(signedDataStream, signedPayload);
            CborEncoder.encodeItem(signedDataStream, signature);
            byte[] signedData = signedDataStream.toByteArray();

            // === DiceCertChain: [UDS_Pub, DiceChainEntry...] ===
            Map<Object, Object> udsPub = createCoseKeyMap(signingKey);
            byte[] udsPubBytes = udsPub != null ? CborEncoder.encode(udsPub) : new byte[]{(byte)0xA0};

            FastByteArrayOutputStream diceCertChainStream = new FastByteArrayOutputStream(512);
            diceCertChainStream.write(0x81); // Array(1) - just UDS public key
            diceCertChainStream.write(udsPubBytes);
            byte[] diceCertChain = diceCertChainStream.toByteArray();

            // === AuthenticatedRequest: [version: 1, UdsCerts, DiceCertChain, SignedData] ===
            FastByteArrayOutputStream authReqStream = new FastByteArrayOutputStream(8192);
            authReqStream.write(0x84); // Array(4)
            CborEncoder.encodeItem(authReqStream, 1); // version
            authReqStream.write(0xA0); // UdsCerts: empty map (privacy)
            authReqStream.write(diceCertChain); // DiceCertChain
            authReqStream.write(signedData); // SignedData

            return authReqStream.toByteArray();
        } catch (Throwable t) {
            Logger.e("Failed to create CertificateRequestResponse", t);
            return null;
        }
    }

    /**
     * Builds DeviceInfoV3 CBOR map per Android RKP spec.
     * All fields are required by GMS for STRONG integrity.
     */
    public static byte[] createDeviceInfoCbor(
            String brand,
            String manufacturer,
            String product,
            String model,
            String device
    ) {
        try {
            Map<String, Object> map = new LinkedHashMap<>();

            map.put("brand", brand != null ? brand : "google");
            map.put("manufacturer", manufacturer != null ? manufacturer : "Google");
            map.put("product", product != null ? product : "generic");
            map.put("model", model != null ? model : "Pixel");
            map.put("device", device != null ? device : "generic");
            map.put("vb_state", "green");
            map.put("bootloader_state", "locked");
            map.put("vbmeta_digest", UtilKt.getBootHash());
            map.put("os_version", String.valueOf(UtilKt.getOsVersion()));
            map.put("system_patch_level", UtilKt.getPatchLevel());
            map.put("boot_patch_level", UtilKt.getPatchLevel());
            map.put("vendor_patch_level", UtilKt.getPatchLevel());
            map.put("security_level", "tee");
            map.put("fused", 1);

            byte[] result = CborEncoder.encode(map);
            return result;

        } catch (Throwable t) {
            Logger.e("Failed to create DeviceInfo CBOR", t);
            return null;
        }
    }
}
