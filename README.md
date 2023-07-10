# AIDIALabs.Security.Crypto
Password and Data encryption library for .Net 6

## Usage ##

### Password with SHA1 encryption ###

```
EncryptionProvider.SHA1Encrypt(string clearPassword);
```

### Password with SHA256 encryption ###

```
EncryptionProvider.SHA256Encrypt(string clearPassword);
```

### Password with SHA256+Salt ###

Three types of Salts

1. Before
2. After
3. Both

Usage
```
EncryptionProvider.SHA256Encrypt(string value, string salt, SaltType type);
```

For `SaltType.Both` you can use also
```
EncryptionProvider.SHA256Encrypt(string value, string salt);
```

In Addvance you can do 3DES `Decrypt` and `Encrypt` also. 
