/*
 * Simple Arduino Sketch to demonstrate how to use
 * Symmetrical Authenticated Encryption with Associated Data (AEAD)
 * Demo uses AES 256 as the cipher, and GCM as the cipher mode
 */

#include <Crypto.h>
//#include <CryptoLW.h>
#include <AES.h>
#include <GCM.h>
//#include <RNG.h>
//#include <TransistorNoiseSource.h>
//#include <string.h>

GCM<AES256> *gcmaes256 = 0;

// The plain text we want to encrypt then decrypt
const size_t  messageSize   = 44;
const char*   messagePlain  = "The Quick Brown Fox Jumps Over The Lazy Dog.";

// The key we want to use (eg. a salted hash of a password)
const char*   key           = "DEMO ONLY, DON'T HARDCODE KEYS!!";

// The "Associated Data" in AEAD
// Decryption requires the same associated data used in encryption
const size_t  authDataSize  = 13;
const char*   authData      = "Hello, World!";

// An initialization vector to add entropy to the encryption process
// Decryption requires the same init vector used in encryption
const size_t  initVecSize   = 12;
      char*   initVector    = "1a2b3c4d5e6f";

// Begin demo
void setup() {
  Serial.begin(2000000);
  delay(4000);
  Serial.println(" ### Now starting Cipher/AEAD demonstration with AES256-GCM");
  
  // initialize / allocate variables
  gcmaes256 = new GCM<AES256>();  // The cipher we will be using
  char*     cipherText;           // A Buffer to store Encrypted text        
  char*     decryptedText;        // A Buffer to store Decrypted text
  uint8_t*  authTag;              // Stores the authtag generated post-encrypt
  size_t    authTagSize = (size_t)gcmaes256->tagSize(); // authtag size determined by cipher

  // Allocate buffers
  cipherText    = (char *)    malloc(messageSize);
  decryptedText = (char *)    malloc(messageSize);
  authTag       = (uint8_t *) malloc(authTagSize);
  
  Serial.println("\n ### The text we want to encrypt:");
  for (int i = 0; i < messageSize; i++) Serial.print((char)messagePlain[i]);

  Serial.println("\n\n ### Cipher checking key...");
  if (gcmaes256->setKey(key, gcmaes256->keySize()))
    Serial.println("Key valid");
  else
    Serial.println("Key not supported");
  
  Serial.println(" ### Key: ");
  for (int i = 0; i < 32; i++) Serial.print((char)key[i]);

  Serial.println("\n\n ### Our Associated Data:");
  for (int i = 0; i < authDataSize; i++) Serial.print((char)authData[i]);

  Serial.println("\n\n ### Starting Initialization Vector:");
  for (int i = 0; i < initVecSize; i++) Serial.print((char)initVector[i]);

  Serial.println("\n\n ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ");
  Serial.println(" ### Now Encrypting");

  useCypherToEncrypt(
    gcmaes256,
    (uint8_t *)messagePlain,
    messageSize,
    (uint8_t *)key,
    (uint8_t *)initVector,
    initVecSize,
    (uint8_t *)cipherText,
    (uint8_t *)authData,
    authDataSize,
    (uint8_t *)authTag,
    authTagSize
  );

  Serial.println(" ### Encrypted Cipher Text:");
  for (int i = 0; i < messageSize; i++) Serial.print((char)cipherText[i]);

  Serial.println("\n ### Encrypted Cipher Text (as decimal):");
  for (int i = 0; i < messageSize; i++) Serial.print((uint8_t)cipherText[i]);

  Serial.println("\n ### Authentication Tag:");
  for (int i = 0; i < authTagSize; i++) Serial.print((uint8_t)authTag[i]);

  Serial.println("\n\n ### Now Decrypting");

  useCypherToDecrypt(
    gcmaes256,
    (uint8_t *)cipherText,
    messageSize,
    (uint8_t *)key,
    (uint8_t *)initVector,
    initVecSize,
    (uint8_t *)decryptedText,
    (uint8_t *)authData,
    authDataSize,
    (uint8_t *)authTag,
    authTagSize
  );

  Serial.println(" ### Decrypted Cipher Text:");
  for (int i = 0; i < messageSize; i++) Serial.print((char)decryptedText[i]);

  Serial.println("\n\n ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ");
  Serial.println(" ### What happens if we use the same initialization vector to encrypt?");
  char* sameIVcipherText;
  sameIVcipherText = (char *)malloc(messageSize);
  useCypherToEncrypt(
    gcmaes256,
    (uint8_t *)messagePlain,
    messageSize,
    (uint8_t *)key,
    (uint8_t *)initVector,
    initVecSize,
    (uint8_t *)sameIVcipherText,
    (uint8_t *)authData,
    authDataSize,
    (uint8_t *)authTag,
    authTagSize
  );

  Serial.println(" ### Encrypted Cipher Text with same iv:");
  for (int i = 0; i < messageSize; i++) Serial.print((char)sameIVcipherText[i]);

  Serial.println("\n ### Encrypted Cipher Text with same iv (as decimal):");
  for (int i = 0; i < messageSize; i++) Serial.print((uint8_t)sameIVcipherText[i]);
  Serial.println("\n ### Cipher Text from before (as decimal):");
  for (int i = 0; i < messageSize; i++) Serial.print((uint8_t)cipherText[i]);
  Serial.println("\n ### Cipher Texts should always be different even with same key/plainText.");
  Serial.println(" ### ALWAYS USE UNIQUE INITIALIZATION VECTORS FOR EACH ENCRYPT!!");

  Serial.println("\n ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ");
  Serial.println(" ### What happens if we try to decrypt with different associated data from encryption?:");
  Serial.println(" ### Original Associated Data:");
  for (int i=0;i<authDataSize;i++) Serial.print((char)authData[i]);
  char *fakeAuthData;
  fakeAuthData = (char *)malloc(32);
  memset(fakeAuthData, 0x00, 32);
  Serial.println("\n ### Bogus Associated Data:");
  for (int i=0;i<32;i++) Serial.print((uint8_t)fakeAuthData[i]);
  Serial.println();
  useCypherToDecrypt(
    gcmaes256,
    (uint8_t *)cipherText,
    messageSize,
    (uint8_t *)key,
    (uint8_t *)initVector,
    initVecSize,
    (uint8_t *)decryptedText,
    (uint8_t *)fakeAuthData,
    32,
    (uint8_t *)authTag,
    authTagSize
  );
  Serial.println(" ### Associated data is not encrypted.");
  Serial.println(" ### Decryption fails if the inputted AD doesn't match the AD used to encrypt.");
  Serial.println(" ### Recommended to make this unique as well for added entropy:");
  Serial.println(" ### eg. timestamps, non-sensitive database entry ids, etc");

  Serial.println("\n ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ");
  Serial.println(" ### What happens if we try to decrypt with a bogus auth tag?");
  Serial.println(" ### Original Authentication Tag:");
  for (int i=0;i<authDataSize;i++) Serial.print((uint8_t)authTag[i]);
  free(fakeAuthData);
  fakeAuthData = (char *)malloc(32);
  memset(fakeAuthData, 0x00, 32);
  Serial.println("\n ### Bogus Authentication Tag:");
  for (int i=0;i<32;i++) Serial.print((uint8_t)fakeAuthData[i]);
  Serial.println();
  useCypherToDecrypt(
    gcmaes256,
    (uint8_t *)cipherText,
    messageSize,
    (uint8_t *)key,
    (uint8_t *)initVector,
    initVecSize,
    (uint8_t *)decryptedText,
    (uint8_t *)authData,
    authDataSize,
    (uint8_t *)fakeAuthData,
    authTagSize
  );
  Serial.println(" ### The Authentication Tag is generated post-encryption.");
  Serial.println(" ### When text is decrypted it is checked to see if would generate");
  Serial.println(" ### the same auth tag when encrypted to verify the integrity of the data.");

  Serial.println("\n ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ");
  Serial.println(" ### What about a different initialization vector?");
  Serial.println(" ### Original Initilization Vector:");
  for (int i=0;i<initVecSize;i++) Serial.print((char)initVector[i]);
  fakeAuthData = (char *)malloc(32);
  memset(fakeAuthData, 0xAA, 32);
  Serial.println("\n ### Bogus Initilization Vector:");
  for (int i=0;i<32;i++) Serial.print((uint8_t)fakeAuthData[i]);
  Serial.println();
  useCypherToDecrypt(
    gcmaes256,
    (uint8_t *)cipherText,
    messageSize,
    (uint8_t *)key,
    (uint8_t *)fakeAuthData,
    32,
    (uint8_t *)decryptedText,
    (uint8_t *)authData,
    authDataSize,
    (uint8_t *)authTag,
    authTagSize
  );
  Serial.println(" ### Decryption fails if the Init Vector used to Encrypt");
  Serial.println(" ### does not match the Init Vector used to Decrypt.");

//  Serial.println("\nAuthentication Tag:");
//  for (int i = 0; i < authTagSize; i++) Serial.print((uint8_t)authTag[i]);
  
  // free allocated memory
  free(fakeAuthData);
  free(cipherText);
  free(decryptedText);
  free(authTag);
  return;
}

void loop() {
  delay(100);
}

void useCypherToEncrypt(
  AuthenticatedCipher *cipher,        // Cypher object; e.g. GCM<AES256>, GCM<Speck>, etc.
  const uint8_t*  plainText,          // the text to be encrypted
  const size_t    plainTextNumBytes,  // size of text
  const uint8_t*  key,                // the key to encrypt the text (eg salted hash of password)
  const uint8_t*  initVector,         // Make unique for every encrypt for non-deterministic behavior
  const size_t    initVectorNumBytes, // size of initialization vector
  uint8_t*        outputCypherText,   // output character buffer with encrypted text
  uint8_t*        authData,           // associated data to add that is not encrypted, but authenticated
  size_t          authDataNumBytes,   // size of associated data
  uint8_t*        authTag,            // the computed, authenticated tag of the encrypted data
  size_t          authTagNumBytes     // size of the authentication tag
) {
  crypto_feed_watchdog();

  cipher->setKey(key, cipher->keySize());
  cipher->setIV(initVector, initVectorNumBytes);
  cipher->addAuthData(authData, authDataNumBytes);
  cipher->encrypt(outputCypherText, plainText, plainTextNumBytes);
  cipher->computeTag(authTag, authTagNumBytes);
  cipher->clear();

  return;
}

void useCypherToDecrypt(
  AuthenticatedCipher *cipher,        // Cypher object; e.g. GCM<AES256>, GCM<Speck>, etc.
  const uint8_t*  cypherText,         // the encrypted text to be decrypted
  const size_t    cypherTextNumBytes, // size of text
  const uint8_t*  key,                // the key to encrypt the text (eg salted hash of password)
  const uint8_t*  initVector,         // Make unique for every encrypt for non-deterministic behavior
  const size_t    initVectorNumBytes, // size of initialization vector
  uint8_t*        outputPlainText,    // output character buffer with plain text
  uint8_t*        authData,           // associated data to add that is not encrypted, but authenticated
  size_t          authDataNumBytes,   // size of associated data
  uint8_t*        authTag,            // the computed, authenticated tag of the encrypted data
  size_t          authTagNumBytes     // size of the authentication tag
) {
  crypto_feed_watchdog();
  
  cipher->setKey(key, cipher->keySize());
  cipher->setIV(initVector, initVectorNumBytes);
  cipher->addAuthData(authData, authDataNumBytes);
  cipher->decrypt(outputPlainText, cypherText, cypherTextNumBytes);

  // Check integrity of decrypted output, discard if authentication fails
  if (!cipher->checkTag(authTag, authTagNumBytes)) {
    // Wipe output buffer
    memset(outputPlainText, 0x00, cypherTextNumBytes);
    Serial.println("CIPHER FAILED TO AUTHENTICATE, DATA SOURCE CANNOT BE VERIFIED!");
  }
  cipher->clear();
  return;
}
