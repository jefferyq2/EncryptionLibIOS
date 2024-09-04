import Foundation
import CommonCrypto

@ObjCName("Encryption:")
public class Encryption {
    
    public init() {}
    private let client = URLSession.shared
    
    @ObjCName("timeBasedEncrypt:")
    public func timeBasedEncrypt(document: String, url: String, secret: String, version: String, completion: @escaping (Result<(String, TimeInterval), Error>) -> Void) {
        let hashFromDocument = getHashSHA(message: document)
        let savedHash = getFromSharedPreferences(key: "hash")
        
        if savedHash != hashFromDocument {
            saveToSharedPreferences(key: "hash", value: hashFromDocument)
        }
        
        var getNewTokenFlag = false
        let savedSecret = getFromSharedPreferences(key: "secret")
        let savedVersion = getFromSharedPreferences(key: "version")
        var appToken = getFromSharedPreferences(key: "token") ?? ""
        
        if savedSecret != secret || savedVersion != version {
            saveToSharedPreferences(key: "secret", value: secret)
            saveToSharedPreferences(key: "version", value: version)
            getNewTokenFlag = true
        }
        
        if getNewTokenFlag {
            applicationAuthenticate(url: url, secret: secret, version: version) { result in
                switch result {
                case .success(let token):
                    appToken = token
                    self.saveToSharedPreferences(key: "token", value: token)
                    self.processTimeBasedEncrypt(document: document, url: url, hashFromDocument: hashFromDocument, appToken: appToken, completion: completion)
                case .failure(let error):
                    completion(.failure(error))
                }
            }
        } else {
            processTimeBasedEncrypt(document: document, url: url, hashFromDocument: hashFromDocument, appToken: appToken, completion: completion)
        }
    }
    
    private func processTimeBasedEncrypt(document: String, url: String, hashFromDocument: String, appToken: String, completion: @escaping (Result<(String, TimeInterval), Error>) -> Void) {
        timeSecret(url: url, hash: hashFromDocument, token: appToken) { result in
            switch result {
            case .success(let (timeSecret, timeRemaining)):
                do {
                    let control = self.createControlByte(isDynamic: true)
                    let documentEncrypt = try self.staticEncrypt(secret: timeSecret, document: document, documentType: 0)
                    var documentBuffer = Data(control)
                    documentBuffer.append(documentEncrypt.data(using: .utf8)!)
                    let documentBase64 = documentBuffer.base64EncodedString()
                    completion(.success((documentBase64, timeRemaining)))
                } catch {
                    completion(.failure(error))
                }
            case .failure(let error):
                completion(.failure(error))
            }
        }
    }
    
    public func saveToSharedPreferences(key: String, value: String) {
        UserDefaults.standard.set(value, forKey: key)
    }

    public func getFromSharedPreferences(key: String) -> String? {
        return UserDefaults.standard.string(forKey: key)
    }
    
    private func timeSecret(url: String, hash: String, token: String, completion: @escaping (Result<(String, TimeInterval), Error>) -> Void) {
        guard let savedHash = getFromSharedPreferences(key: "hash") else {
            completion(.failure(NSError(domain: "Hash no encontrado", code: -1, userInfo: nil)))
            return
        }
        
        if savedHash != hash {
            completion(.failure(NSError(domain: "Hash no coincide", code: -1, userInfo: nil)))
            return
        }
        
        getDataFromApi(url: url, hash: hash, token: token) { result in
            switch result {
            case .success(let jsonResponse):
                self.saveToSharedPreferences(key: "jsonResponse", value: jsonResponse)
                
                do {
                    let jsonObject = try JSONSerialization.jsonObject(with: Data(jsonResponse.utf8), options: []) as? [String: Any]
                    guard let ticket = jsonObject?["ticket"] as? [String: Any],
                          let timeBasedToken = ticket["timeBasedToken"] as? [String: Any],
                          let secret = timeBasedToken["secret"] as? String,
                          let tsCreated = timeBasedToken["tsCreated"] as? String,
                          let validityPeriod = timeBasedToken["validityPeriod"] as? TimeInterval,
                          let tolerance = timeBasedToken["tolerance"] as? TimeInterval else {
                        completion(.failure(NSError(domain: "Missing data", code: -1, userInfo: nil)))
                        return
                    }

                    let tsCreatedMillis = self.parseIsoDateWithOptionalOffset(dateString: tsCreated)
                    let now = Date().timeIntervalSince1970 * 1000
                    let elapsed = now - (now - tsCreatedMillis).truncatingRemainder(dividingBy: tolerance) + tolerance / 2
                    let timeKey = elapsed - (elapsed - tsCreatedMillis).truncatingRemainder(dividingBy: validityPeriod)
                    
                    let timeRemaining = validityPeriod - ((now - timeKey).truncatingRemainder(dividingBy: validityPeriod))
                    completion(.success((secret + String(Int(timeKey)), timeRemaining)))
                } catch {
                    completion(.failure(error))
                }
            case .failure(_):
                if let jsonResponse = self.getFromSharedPreferences(key: "jsonResponse") {
                    do {
                        let jsonObject = try JSONSerialization.jsonObject(with: Data(jsonResponse.utf8), options: []) as? [String: Any]
                        guard let ticket = jsonObject?["ticket"] as? [String: Any],
                              let timeBasedToken = ticket["timeBasedToken"] as? [String: Any],
                              let secret = timeBasedToken["secret"] as? String,
                              let tsCreated = timeBasedToken["tsCreated"] as? String,
                              let validityPeriod = timeBasedToken["validityPeriod"] as? TimeInterval,
                              let tolerance = timeBasedToken["tolerance"] as? TimeInterval else {
                            completion(.failure(NSError(domain: "Missing data", code: -1, userInfo: nil)))
                            return
                        }

                        let tsCreatedMillis = self.parseIsoDateWithOptionalOffset(dateString: tsCreated)
                        let now = Date().timeIntervalSince1970 * 1000
                        let elapsed = now - (now - tsCreatedMillis).truncatingRemainder(dividingBy: tolerance) + tolerance / 2
                        let timeKey = elapsed - (elapsed - tsCreatedMillis).truncatingRemainder(dividingBy: validityPeriod)
                        
                        let timeRemaining = validityPeriod - ((now - timeKey).truncatingRemainder(dividingBy: validityPeriod))
                        completion(.success((secret + String(Int(timeKey)), timeRemaining)))
                    } catch {
                        completion(.failure(error))
                    }
                } else {
                    completion(.failure(NSError(domain: "No hubo respuesta de la API y no se encontró información guardada en dispositivo", code: -1, userInfo: nil)))
                }
            }
        }
    }
    
    private func createControlByte(isDynamic: Bool = false) -> [UInt8] {
        var randomByte: UInt8 = 0
        let randomStatus = SecRandomCopyBytes(kSecRandomDefault, 1, &randomByte)
        
        if randomStatus != errSecSuccess {
            fatalError("Error generating random byte")
        }
        
        let type: UInt8 = isDynamic ? 1 : 0
        let byteSum = (randomByte & 0xFE) + type
        let positiveByteSum = byteSum & 0xFF
        
        return [positiveByteSum]
    }
    
    private func staticEncrypt(secret: String, document: String, documentType: UInt8) throws -> String {
        guard !document.isEmpty else {
            throw NSError(domain: "Document invalid", code: -1, userInfo: nil)
        }
        
        let encryptor = try SimpleEncryptor(secretKey: secret)
        let documentEncrypt = try encryptor.encrypt(plainText: document)
        let manifest: [UInt8] = [documentType]
        var combinedBuffer = Data(manifest)
        combinedBuffer.append(documentEncrypt.data(using: .utf8)!)
        return combinedBuffer.base64EncodedString()
    }
    
    public func getDataFromApi(url: String, hash: String, token: String, completion: @escaping (Result<String, Error>) -> Void) {
        guard let fullUrl = URL(string: "\(url)api/v1/secure/timebasedtoken/ticket?hash=\(hash)") else {
            completion(.failure(NSError(domain: "Invalid URL", code: -1, userInfo: nil)))
            return
        }
        
        var request = URLRequest(url: fullUrl)
        request.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        
        let task = client.dataTask(with: request) { data, response, error in
            if let error = error {
                completion(.failure(error))
                return
            }
            
            guard let data = data, let responseString = String(data: data, encoding: .utf8) else {
                completion(.failure(NSError(domain: "No data or failed to decode data", code: -1, userInfo: nil)))
                return
            }
            
            completion(.success(responseString))
        }
        
        task.resume()
    }
    
    public func getHashSHA(message: String) -> String {
        let base64String = String(message)
        guard let data = Data(base64Encoded: base64String) else {
            fatalError("Invalid Base64 string")
        }
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
        }
        return hash.map { String(format: "%02x", $0) }.joined()
    }
    
    private func parseIsoDateWithOptionalOffset(dateString: String) -> Double {
        let isoFormatWithOffset = DateFormatter()
        isoFormatWithOffset.locale = Locale(identifier: "en_US_POSIX")
        isoFormatWithOffset.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSXXX"
        
        let isoFormatWithoutOffset = DateFormatter()
        isoFormatWithoutOffset.locale = Locale(identifier: "en_US_POSIX")
        isoFormatWithoutOffset.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
        
        let tsCreatedDate: Date?
        if let date = isoFormatWithOffset.date(from: dateString) {
            tsCreatedDate = date
        } else if let date = isoFormatWithoutOffset.date(from: dateString) {
            tsCreatedDate = date
        } else {
            fatalError("Invalid date format")
        }
        
        return tsCreatedDate?.timeIntervalSince1970 ?? 0 * 1000
    }

    private func applicationAuthenticate(url: String, secret: String, version: String, completion: @escaping (Result<String, Error>) -> Void) {
        guard let fullUrl = URL(string: "\(url)api/v1/authenticate/mobile/application") else {
            completion(.failure(NSError(domain: "Invalid URL", code: -1, userInfo: nil)))
            return
        }
        
        var request = URLRequest(url: fullUrl)
        request.httpMethod = "POST"
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")
        
        let json: [String: Any] = ["secret": secret, "version": version]
        do {
            let jsonData = try JSONSerialization.data(withJSONObject: json, options: [])
            request.httpBody = jsonData
        } catch {
            completion(.failure(error))
            return
        }
        
        let task = client.dataTask(with: request) { data, response, error in
            if let error = error {
                completion(.failure(error))
                return
            }
            
            guard let data = data, let jsonObject = try? JSONSerialization.jsonObject(with: data, options: []) as? [String: Any], let token = jsonObject["token"] as? String else {
                completion(.failure(NSError(domain: "Invalid response", code: -1, userInfo: nil)))
                return
            }
            
            completion(.success(token))
        }
        
        task.resume()
    }
}

public class SimpleEncryptor {
    private let key: Data
    
    public init(secretKey: String) throws {
        guard let keyData = secretKey.data(using: .utf8) else {
            throw NSError(domain: "Invalid secret key", code: -1, userInfo: nil)
        }
        
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        keyData.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(keyData.count), &hash)
        }
        
        self.key = Data(hash)
    }
    
    public func encrypt(plainText: String) throws -> String {
        let modifiedPlainText = "\"'\(plainText)'\""
        let iv = try generateRandomBytes(count: 16)
        
        var encryptedBytes = [UInt8](repeating: 0, count: modifiedPlainText.count + kCCBlockSizeAES128)
        var numBytesEncrypted: size_t = 0
        
        let cryptStatus = key.withUnsafeBytes { keyBytes in
            iv.withUnsafeBytes { ivBytes in
                CCCrypt(
                    CCOperation(kCCEncrypt),
                    CCAlgorithm(kCCAlgorithmAES),
                    CCOptions(kCCOptionPKCS7Padding),
                    keyBytes.baseAddress, kCCKeySizeAES256,
                    ivBytes.baseAddress,
                    modifiedPlainText, modifiedPlainText.count,
                    &encryptedBytes, encryptedBytes.count,
                    &numBytesEncrypted
                )
            }
        }
        
        guard cryptStatus == kCCSuccess else {
            throw NSError(domain: "Error encrypting", code: Int(cryptStatus), userInfo: nil)
        }
        
        encryptedBytes.removeSubrange(numBytesEncrypted..<encryptedBytes.count)
        let ivHex = iv.map { String(format: "%02x", $0) }.joined()
        let encryptedBase64 = Data(encryptedBytes).base64EncodedString()
        let result = ivHex + encryptedBase64
        let hmac = try generateHmac(key: key, data: result.data(using: .utf8)!)
        let hmacHex = hmac.map { String(format: "%02x", $0) }.joined()
        let finalResult = hmacHex + result
        return finalResult
    }
    
    private func generateRandomBytes(count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        guard status == errSecSuccess else {
            throw NSError(domain: "Error generating random bytes", code: Int(status), userInfo: nil)
        }
        return Data(bytes)
    }
    
    private func generateHmac(key: Data, data: Data) throws -> Data {
        var hmac = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), key.bytes, key.count, data.bytes, data.count, &hmac)
        return Data(hmac)
    }
}

extension Data {
    var bytes: [UInt8] {
        return [UInt8](self)
    }
}

