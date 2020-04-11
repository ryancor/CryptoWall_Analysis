#include <stdio.h>
#include <Windows.h>
#include <wincrypt.h>
#include <sstream>
#include <fstream>


HCRYPTPROV hProvider = NULL;
HCRYPTKEY hKey = NULL;

BOOL ReadBlocksFromFile(HANDLE hFile, void *Buffer, DWORD BufSize, DWORD *BytesRead)
{
  if (BytesRead)
  {
    *BytesRead = 0;
  }

  LPBYTE pBuffer = (LPBYTE) Buffer;
  DWORD dwRead;

  while (BufSize > 0)
  {
    if (!ReadFile(hFile, pBuffer, BufSize, &dwRead, NULL))
    {
      return FALSE;
    }

    if (dwRead == 0)
    {
      break;
    }

    pBuffer += dwRead;
    BufSize -= dwRead;

    if (BytesRead)
    {
      *BytesRead += dwRead;
    }
  }

  return TRUE;
}

BOOL InitializeProvider(LPCTSTR pszProvider, DWORD dwProvType)
{
  if(hProvider != NULL)
  {
    if(!CryptReleaseContext(hProvider, 0))
    {
      return 0;
    }
  }
  return CryptAcquireContext(&hProvider, NULL, pszProvider, dwProvType, CRYPT_VERIFYCONTEXT);
}

BOOL ImportPrivateKey(LPTSTR filename)
{
  DWORD dwBufferLen = 0, cbKeyBlob = 0;
  LPBYTE pbBuffer = NULL, pbKeyBlob = NULL;

  std::ostringstream sstream;
  std::ifstream fs(filename);
  sstream << fs.rdbuf();
  const std::string str(sstream.str());
  const char* szPemPrivKey = str.c_str();

  if (!CryptStringToBinaryA(szPemPrivKey, 0,
    CRYPT_STRING_BASE64HEADER, NULL,
    &dwBufferLen,
    NULL, NULL))
  {
    printf("Failed to convert BASE64 private key. Error 0x%.8X\n", GetLastError());
    return FALSE;
  }

  pbBuffer = (LPBYTE) LocalAlloc(0, dwBufferLen);
  if (!CryptStringToBinaryA(szPemPrivKey, 0,
    CRYPT_STRING_BASE64HEADER, pbBuffer,
    &dwBufferLen,
    NULL, NULL))
  {
    printf("Failed to convert BASE64 private key. Error 0x%.8X\n", GetLastError());
    return FALSE;
  }

  if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
    PKCS_RSA_PRIVATE_KEY, pbBuffer,
    dwBufferLen, 0, NULL,
    NULL, &cbKeyBlob))
  {
    printf("Failed to parse private key. Error 0x%.8X\n", GetLastError());
    return FALSE;
  }

  pbKeyBlob = (LPBYTE) LocalAlloc(0, cbKeyBlob);
  if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
    PKCS_RSA_PRIVATE_KEY, pbBuffer,
    dwBufferLen, 0, NULL,
    pbKeyBlob, &cbKeyBlob))
  {
    printf("Failed to parse private key. Error 0x%.8X\n", GetLastError());
    return FALSE;
  }

  if (!CryptImportKey(hProvider, pbKeyBlob, cbKeyBlob, NULL, 0, &hKey))
  {
    printf("CryptImportKey for private key failed with error 0x%.8X\n", GetLastError());
    return FALSE;
  }

  return TRUE;
}

BOOL DecryptFromFile(char *argv)
{
  DWORD bytesRead;
  const UINT blockSize = 214;
  LPBYTE fileBuffer = new BYTE[blockSize+500];

  HANDLE hFile = CreateFile(argv, GENERIC_READ,
    0x7, NULL,
    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
    NULL
  );

  if(!ReadBlocksFromFile(hFile, fileBuffer, blockSize, &bytesRead))
  {
    return FALSE;
  }

  if (!CryptDecrypt(hKey, NULL, FALSE, 0, fileBuffer, &bytesRead))
  {
      printf("[-] CryptDecrypt failed with error 0x%.8X\n", GetLastError());
      //return FALSE;
  }

  for(int i = 0; i < bytesRead; i++)
  {
    printf("%c ", fileBuffer[i]);
  }

  return TRUE;
}

int main(int argc, char **argv)
{
  if(argc < 3)
  {
    printf("[!] Usage: %s [priv_key] [encrypted_file]\n", argv[0]);
    return -1;
  }

  if(!InitializeProvider(MS_ENHANCED_PROV, PROV_RSA_FULL))
  {
    printf("[-] Could not initialize provider\n");
    return -1;
  }

  printf("[+] Initialized crypto provider\n");

  if(!ImportPrivateKey(argv[1]))
  {
    return -1;
  }

  printf("[+] Successfully imported private key from PEM file\n");

  if(DecryptFromFile(argv[2]))
  {
    printf("\n[+] Successfully decrypted file\n");
  }

  return 0;
}
