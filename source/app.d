import std.stdio;
import clid;
import clid.parse;
import ranonrat.cryptod;
import clid.validate;
import std.path;
import std.file;
import std.array;
import std.utf;
import std.digest.sha;
import std.base64;
import std.string;

const string versionProject = "1.0.0";
string baseQypritDir = "";
string qypritIdentitiesDir = "";
string qypritFriendIdentitiesDir = "";
string defaultPassword = "qyprit-password";
private struct CmdArguments
{
	@Parameter("password", 'p')  // works
	@Description("This just specifies the password to access to your pem(or encrypt it)")
	 // this is incase the pem has a password
	string password;

	@Parameter("identity")  // this is just to call an identity  works
	@Description(
		"Use this to select your identity(it specifies what you are going to be using to sign or decrypt messages)")
	string identity;

	@Parameter("new-identity")  /*works already*/
	@Description("Create a new identity(specify the password with the -p flag)")
	string newIdentity;

	@Parameter("remove-identity")
	@Description("Removes the identity")
	string removeIdentity;

	@Parameter("list-identities")
	@Description("list your current identities")
	bool listIdentities;

	// friends
	@Parameter("friend")  // works
	@Description("use this to select your friend(will be used to encrypt or verify messages)")
	string friend = "";

	@Parameter("new-friend")  // works already
	@Description("Adds a new friend")
	string newFriend;

	@Parameter("remove-friend")
	@Description("removes the friend")
	string removeFriend;

	@Parameter("list-friend",)
	@Description("List your friends")
	bool listFriend;

	// actions
	@Parameter("sign", 's')  // works already
	@Description("Sign the message(doesnt encrypt, requires identity)")
	bool sign;

	@Parameter("encrypt", 'e')  //works already
	@Description("Encrypt message(requires identity and friend)")
	bool encrypt;
	// 
	@Parameter("verify")  // works already
	@Description("Verifies message(requires friend)")
	bool verify;

	@Parameter("decrypt")  // works already
	@Description("Decrypts message(requires identity and friend)")
	bool decrypt;
	// this will print your public key or the public key of another person
	@Parameter("public-key")  // works already
	@Description("Prints identity key or friend key(you must have either of those selected)")
	bool pk;

	// Extra stuff
	@Parameter("version", 'v')  // works already
	bool versionProject;

	@Parameter("setup")  // works already
	bool setup;

}

struct CryptographicIdentity
{

	OpenSslKey encapsulationKey;
	OpenSslKey signatureKey;
	static CryptographicIdentity create()
	{
		CryptographicIdentity output;
		output.encapsulationKey = GenerateMLKemKey(TypeMLkem.ML_KEM_1024);
		output.signatureKey = GenerateOQSProvider("ML-DSA-87");
		return output;
	}

	void savePrivateKeys(string baseDir, string password)
	{
		if (password.length == 0)
			password = defaultPassword;

		string pathSignatureKey = absolutePath("signature.pem", baseDir);
		string pathEncapsulationKey = absolutePath("encapsulation.pem", baseDir);

		auto fEncapsulationKey = File(pathEncapsulationKey, "wrb");
		auto fSignatureKey = File(pathSignatureKey, "wrb");

		auto privEnc = this.encapsulationKey.privateKeyToPemString(password);
		auto privSign = this.signatureKey.privateKeyToPemString(password);

		fEncapsulationKey.write(privEnc);
		fSignatureKey.write(privSign);
	}

	void savePublicKeys(string baseDir)
	{
		string pathSignatureKey = absolutePath("pub-signature.pem", baseDir);
		string pathEncapsulationKey = absolutePath("pub-encapsulation.pem", baseDir);

		auto fEncapsulationKey = File(pathEncapsulationKey, "wrb");
		auto fSignatureKey = File(pathSignatureKey, "wrb");

		auto pubEnc = this.encapsulationKey.publicKeyToPemString();
		auto pubSign = this.signatureKey.publicKeyToPemString();

		fEncapsulationKey.write(pubEnc);
		fSignatureKey.write(pubSign);
	}

	void loadPublicKeys(string baseDir)
	{
		string pathEncapsulationKey = absolutePath("pub-encapsulation.pem", baseDir);
		string pathSignatureKey = absolutePath("pub-signature.pem", baseDir);

		this.encapsulationKey.parsePublicPemString(readText(pathEncapsulationKey));
		this.signatureKey.parsePublicPemString(readText(pathSignatureKey));
	}

	void loadPrivateKeys(string baseDir, string password)
	{
		if (password.length == 0)
			password = defaultPassword;

		string pathEncapsulationKey = absolutePath("encapsulation.pem", baseDir);
		string pathSignatureKey = absolutePath("signature.pem", baseDir);

		this.encapsulationKey.parsePrivatePemString(readText(pathEncapsulationKey), password);
		this.signatureKey.parsePrivatePemString(readText(pathSignatureKey), password);
	}

}

void init()
{

	baseQypritDir = expandTilde("~/.qyprit");
	qypritIdentitiesDir = absolutePath("identities", baseQypritDir);
	qypritFriendIdentitiesDir = absolutePath("friend", baseQypritDir);

}

bool verifyFilesExists()
{
	return exists(baseQypritDir) &&
		exists(qypritFriendIdentitiesDir) &&
		exists(qypritIdentitiesDir);

}

void setup()
{
	if (verifyFilesExists())
	{
		writeln("everything is already setup");
		return;
	}
	try
	{
		mkdir(baseQypritDir);
		mkdir(qypritIdentitiesDir);
		mkdir(qypritFriendIdentitiesDir);
		writeln("Done :)");

	}
	catch (Exception e)
	{
		writeln("Caught exception: ", e.msg);
	}

}

void printFormatedSection(string part, string content)
{
	writeln("-----BEGIN ", part, "-----");
	writeln(strip(content));
	writeln("-----END ", part, "-----");
}

void printFormatedKeys(string baseDir)
{

	string pathEncapsulationKey = absolutePath("pub-encapsulation.pem", baseDir);
	string pathSignatureKey = absolutePath("pub-signature.pem", baseDir);

	writeln("Created using qyprit@", versionProject);
	printFormatedSection("PUBLIC ENCAPSULATION KEY", readText(pathEncapsulationKey));
	printFormatedSection("PUBLIC SIGNATURE KEY", readText(pathSignatureKey));

}

void newIdentity(string identity, string password)
{
	try
	{
		string identityPath = absolutePath(identity, qypritIdentitiesDir);
		if (exists(identityPath))
		{
			writeln("Identity ", identity, " already exists");
			return;
		}
		mkdir(identityPath);

		auto cryptoIdentity = CryptographicIdentity.create();
		cryptoIdentity.savePrivateKeys(identityPath, password);
		cryptoIdentity.savePublicKeys(identityPath);

		writeln(identity, " has been created");
	}
	catch (Exception e)
	{
		writeln("Caught exception: ", e.msg);
	}
}

void removeIdentity(string identity)
{
	try
	{
		string identityPath = absolutePath(identity, qypritIdentitiesDir);
		if (exists(identityPath))
		{
			writeln("Identity ", identity, " does not exists");
			return;
		}
		rmdirRecurse(identityPath);
	}
	catch (Exception e)
	{
		writeln("Caught exception: ", e.msg);
	}
}

void listIdentities()
{
	try
	{
		foreach (entry; dirEntries(qypritIdentitiesDir.dup, SpanMode.shallow))
		{
			writeln("\t-", baseName(entry.name));
		}

	}
	catch (Exception e)
	{
		writeln("Caught exception: ", e.msg);
	}
}

void pubKeyIdentity(string identity)
{
	try
	{
		string identityPath = absolutePath(identity, qypritIdentitiesDir);
		if (!exists(identityPath))
		{
			writeln("The identity: ", identity, "does not exists");
			return;
		}
		printFormatedKeys(identityPath);
	}
	catch (Exception e)
	{
		writeln("Caught exception: ", e.msg);
	}
}

//this also works for updating that path :)
void newFriend(string friend)
{
	try
	{
		string friendPath = absolutePath(friend, qypritFriendIdentitiesDir);
		// this should only be saving the public keys not anything else
		if (!exists(friendPath))
			mkdir(friendPath);

		string pathEncapsulationPubKey = absolutePath("pub-encapsulation.pem", friendPath);
		string pathSignaturePubKey = absolutePath("pub-signature.pem", friendPath);

		auto fEncapsulationPubKey = File(pathEncapsulationPubKey, "wrb");
		auto fSignaturePubKey = File(pathSignaturePubKey, "wrb");

		writeln("Please paste the public signature and encapsulation key");
		stdout.flush();
		string pem;
		bool beginWrittingPem = false;
		string line = readln();
		for (; strip(line) != "-----END PUBLIC SIGNATURE KEY-----"; line = readln())
		{

			if (line == "-----END PUBLIC ENCAPSULATION KEY-----\n")
			{
				fEncapsulationPubKey.write(pem);
				pem = "";
			}

			if (line == "-----BEGIN PUBLIC KEY-----\n")
			{
				beginWrittingPem = true;
			}
			if (beginWrittingPem)
				pem ~= line;
			if (line == "-----END PUBLIC KEY-----\n")
				beginWrittingPem = false;
		}
		if (strip(line) == "-----END PUBLIC SIGNATURE KEY-----")
		{
			fSignaturePubKey.write(pem);
			pem = "";
		}
		writeln("\nNew friend saved");

	}

	catch (Exception e)
	{
		writeln("Caught exception: ", e.msg);
	}
}

void removeFriend(string friend)
{
	try
	{
		string friendPath = absolutePath(friend, qypritFriendIdentitiesDir);
		// this should only be saving the public keys not anything else
		if (!exists(friendPath))
		{
			writeln("The friend: ", friend, "does not exists");
			return;
		}
		rmdirRecurse(friendPath);
	}
	catch (Exception e)
	{
		writeln("Caught exception: ", e.msg);
	}
}

void listFriends()
{
	try
	{
		foreach (entry; dirEntries(qypritFriendIdentitiesDir, SpanMode.shallow))
		{
			writeln("\t-", baseName(entry.name));
		}

	}
	catch (Exception e)
	{
		writeln("Caught exception: ", e.msg);
	}
}

void pubKeyFriend(string friend)
{
	try
	{
		string friendPath = absolutePath(friend, qypritIdentitiesDir);
		if (!exists(friendPath))
		{
			writeln("The friend: ", friend, "does not exists");
			return;
		}
		printFormatedKeys(friendPath);

	}
	catch (Exception e)
	{
		writeln("Caught exception: ", e.msg);
	}
}

CryptographicIdentity loadFriend(string friend)
{
	auto output = CryptographicIdentity.create();
	string friendPath = absolutePath(friend, qypritFriendIdentitiesDir);

	if (!exists(friendPath))
		throw new Exception("The friend: " ~ friend ~ "does not exists");

	output.loadPublicKeys(friendPath);
	return output;
}

CryptographicIdentity loadIdentity(string identity, string password)
{
	auto output = CryptographicIdentity.create();
	string identityPath = absolutePath(identity, qypritIdentitiesDir);

	if (!exists(identityPath))
		throw new Exception("The identity: " ~ identity ~ "does not exists");

	output.loadPrivateKeys(identityPath, password);
	return output;
}

string getFullMessage()
{
	writeln("Once you finish your message just write \"(END)\" to end the loop");
	string message = "";

	for (string line = readln(); line != "(END)\n"; line = readln())
		message ~= line.strip() ~ "\n";

	return message;
}

string prepareBytes(ubyte[] content)
{ // the max amount per line is 64 characters
	string output = "";
	string before = Base64.encode(content);
	const size_t next = 64;
	size_t offset = 0;
	for (; offset + next < before.length; offset += next)
		output ~= before[offset .. offset + next] ~ "\n";

	if (offset < before.length)
		output ~= before[offset .. before.length];
	return output;

}

void signMessage(CryptographicIdentity* identity)
{
	string message = getFullMessage();

	auto bMessage = (cast(ubyte[]) message).dup;
	auto hash = sha256Of(bMessage);
	auto signed = identity.signatureKey.signMessage(hash);
	writeln("Created using qyprit@", versionProject);
	printFormatedSection("SIGNATURE", prepareBytes(signed));
	printFormatedSection("MESSAGE", message);

}

//in both cases we always have the final signature of the content :)
void verifyMessage(CryptographicIdentity* friend)
{
	string signature = "";
	string message = "";

	writeln("Paste the contents");

	bool saveSignature = false;
	bool saveMessage = false;
	bool encryptedContents = false;
	for (string line = readln(); strip(line) != "-----END MESSAGE-----"; line = readln())
	{
		if (line == "-----BEGIN SIGNATURE-----\n")
		{
			saveSignature = true;
			continue;
		}
		if (line == "-----BEGIN CIPHER TEXT-----\n")
			encryptedContents = true;
		if (line == "-----BEGIN MESSAGE-----\n")
		{
			saveMessage = true;
			continue;
		}
		if (line == "-----END SIGNATURE-----\n")
			saveSignature = false;

		if (saveSignature)
		{
			signature ~= line.strip();
		}
		if (saveMessage)
		{
			if (encryptedContents)
				message ~= line.strip();
			else
				message ~= line.strip() ~ "\n";

		}
	}
	// if the contents are not encrypted then it doesnt matter
	auto bMessage = (encryptedContents) ?
		Base64.decode(message) :  //
		(cast(ubyte[]) message).dup;

	auto bSignature = Base64.decode(signature);
	auto hash = sha256Of(bMessage);
	if (friend.signatureKey.verifyMessage(hash, bSignature))
	{
		writeln("message seems valid");
		return;
	}
	writeln("invalid message");

}

void encryptMessage(CryptographicIdentity* identity, CryptographicIdentity* friend)
{
	string message = getFullMessage();
	// I should add 64 randomized characters to create noise(later)
	auto sharedSecret = SecureBuffer!ubyte(32, AllocFree.OPENSSL_MALLOC);
	auto cipherText = friend.encapsulationKey.generateSharedSecret(&sharedSecret);

	ubyte[12] iv = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,];
	ubyte[16] tag;
	auto encriptedMessage = AESgcmEncrypt(&sharedSecret, cast(ubyte[]) message, null, iv, tag);
	auto hash = sha256Of(encriptedMessage);
	auto signed = identity.signatureKey.signMessage(hash);
	writeln("Created using qyprit@", versionProject);
	printFormatedSection("SIGNATURE", prepareBytes(signed));
	printFormatedSection("CIPHER TEXT", prepareBytes(cipherText));
	printFormatedSection("TAG", prepareBytes(tag));
	printFormatedSection("MESSAGE", prepareBytes(encriptedMessage));
}

void decryptMessage(CryptographicIdentity* identity, CryptographicIdentity* friend)
{
	string b64EncryptedMessage = "";
	string b64Signature = "";
	string b64CipherText = "";
	string b64Tag = "";
	bool saveSignature = false;
	bool saveMessage = false;
	bool saveCipherText = false;
	bool saveTag = false;
	writeln("please paste the contents");
	for (string line = readln().strip(); line != "-----END MESSAGE-----"; line = readln().strip())
	{
		if (line == "-----BEGIN SIGNATURE-----")
		{
			saveSignature = true;
			continue;
		}
		if (line == "-----BEGIN CIPHER TEXT-----")
		{
			saveCipherText = true;
			continue;
		}
		if (line == "-----BEGIN MESSAGE-----")
		{
			saveMessage = true;
			continue;
		}
		if (line == "-----BEGIN TAG-----")
		{
			saveTag = true;
			continue;
		}
		if (line == "-----END SIGNATURE-----")
		{
			saveSignature = false;
		}
		if (line == "-----END CIPHER TEXT-----")
		{
			saveCipherText = false;
		}
		if (line == "-----END TAG-----")
		{
			saveTag = false;

		}

		if (saveSignature)
			b64Signature ~= line;
		if (saveMessage)
			b64EncryptedMessage ~= line;
		if (saveCipherText)
			b64CipherText ~= line;
		if (saveTag)
			b64Tag ~= line;
	}
	auto bSignature = Base64.decode(b64Signature);
	auto bCipherText = Base64.decode(b64CipherText);
	auto bEncryptedMessage = Base64.decode(b64EncryptedMessage);
	auto bTag = Base64.decode(b64Tag);
	auto hash = sha256Of(bEncryptedMessage);
	if (!friend.signatureKey.verifyMessage(hash, bSignature))
	{
		writeln("Message is not valid");
		return;
	}

	auto sharedSecretRec = SecureBuffer!ubyte(32, AllocFree.OPENSSL_MALLOC);
	identity.encapsulationKey.decryptCipherText(bCipherText, &sharedSecretRec);
	ubyte[16] tag = bTag;
	ubyte[12] iv = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,];
	auto unencrytpedMessage = AESgcmDecrypt(&sharedSecretRec, bEncryptedMessage, null, iv, tag);

	writeln("\nHere are the contents message\n", cast(string)(unencrytpedMessage));

}

void help()
{
	writeln(
		"Qyprit version: " ~ versionProject ~ "
Made by ranon-rat

USAGE:
  qyprit <command> [options]

GLOBAL:
  -p, --password <pass>      Password for the private PEM (on create or load)
  -h, --help                 Show this help
  -v, --version              Show version

SETUP:
  --setup                    Create ~/.qyprit/ and its subdirectories

IDENTITIES (your private keys):
  --new-identity <name>      Create a new identity (use -p for the password)
  --remove-identity <name>   Remove an existing identity
  --list-identities          List your identities
  --identity <name>          Select your identity to sign / decrypt / show pubkey
  --public-key               With --identity prints your pubkey; with --friend the friend's

FRIENDS (other people's public keys):
  --new-friend <name>        Add or update a friend by pasting their pubkeys
  --remove-friend <name>     Remove a friend
  --list-friend              List your friends
  --friend <name>            Select a friend to encrypt / verify

ACTIONS:
  -s, --sign                 Sign a message         (requires --identity)
  --verify                   Verify a signature     (requires --friend)
  -e, --encrypt              Encrypt and sign       (requires --identity and --friend)
  --decrypt                  Decrypt and verify     (requires --identity and --friend)

EXAMPLES:
  qyprit --setup
  qyprit --new-identity alice -p \"my_pass\"
  qyprit --identity alice --sign
  qyprit --identity alice --friend bob --encrypt
  qyprit --identity alice --friend bob --decrypt
  qyprit --friend bob --verify
  qyprit --identity alice --public-key");
}

void main(string[] argv)

{
	init();

	foreach (arg; argv[1 .. $])
	{
		if (arg == "-h" || arg == "--help")
		{
			help();
			return;
		}
	}

	auto args = parseArguments!CmdArguments();

	if (args.versionProject)
	{
		writeln("Qyprit version: ", versionProject, "\nMade by ranon-rat");
		return;
	}
	if (args.setup)
	{
		setup();
		return;
	}
	if (args.newIdentity.length > 0)
	{
		newIdentity(args.newIdentity, args.password);
		return;
	}
	if (args.removeIdentity.length > 0)
	{
		removeIdentity(args.removeIdentity);
	}
	if (args.listIdentities)
	{
		listIdentities();

	}
	if (args.newFriend.length > 0)
	{
		newFriend(args.newFriend);
		return;
	}
	if (args.removeFriend.length > 0)
	{
		removeFriend(args.removeFriend);
	}
	if (args.listFriend)
	{
		listFriends();
	}
	if (args.friend.length > 0 && args.pk)
	{
		pubKeyFriend(args.friend);
		return;
	}
	if (args.identity.length > 0 && args.pk)
	{
		pubKeyIdentity(args.identity);
		return;
	}
	if (args.identity.length > 0 && args.sign)
	{
		try
		{

			auto identity = loadIdentity(args.identity, args.password);
			signMessage(&identity);
		}
		catch (Exception e)
		{
			writeln("Caught exception: ", e.msg);
		}
		return;
	}
	if (args.friend.length > 0 && args.verify)
	{
		try
		{
			auto friend = loadFriend(args.friend);
			verifyMessage(&friend);
		}
		catch (Exception e)
		{
			writeln("Caught exception: ", e.msg);
		}
	}
	if (args.identity.length > 0 && args.friend.length > 0)
	{
		try
		{
			auto identity = loadIdentity(args.identity, args.password);
			auto friend = loadFriend(args.friend);

			if (args.encrypt)
			{
				// the encryption also signs the message :)
				encryptMessage(&identity, &friend);
				return;
			}

			if (args.decrypt)
			{
				decryptMessage(&identity, &friend);
				return;
			}
		}
		catch (Exception e)
		{
			writeln("Caught exception: ", e.msg);
		}

	}

}
