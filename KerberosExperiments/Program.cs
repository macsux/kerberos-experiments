using Kerberos.NET;
using Kerberos.NET.Client;
using Kerberos.NET.Configuration;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;

const string username = "iwaclient@almirex.com";
const string password = "abc";
const string krb5confPath = @"c:\temp\krb5.conf";
const string keytabPath = @"c:\temp\keytab.key";

var credentials = new KerberosPasswordCredential(username, password);

var krb5Config = Krb5Config.Parse(File.ReadAllText(krb5confPath));
var client = new KerberosClient(krb5Config);

var spns = new[] { "http/blah" };
int? startKvno = null;
int? endKvno;
// kvno is the version number of the password of the service account. every time password is changed, it increments/
// entries in keytab are looked up via matching principal name (username or spn) + kvno
// (which are present in unencrypted portion of incoming ticket. if kvno doesn't match incoming ticket's kvno,
// MIT kerberos  won't attempt to decrypt it even if valid key is present

// we will try to do this via both UPN and every SPN associated with the account.
// hopefully one of them will work to get a valid service ticket
var principalNamesToTry = new[] { username }.Union(spns);
foreach (var principalName in principalNamesToTry)
{
    try
    {
        // attempt to retrieve real kvno by obtaining a ticket for itself
        var ticketForSelf = await client.GetServiceTicket(principalName);
        startKvno = ticketForSelf.Ticket.EncryptedPart.KeyVersionNumber;
        break;
    }
    catch (KerberosProtocolException)
    {

    }
}

if (startKvno == null)
{
    Console.WriteLine("Unable to obtain service ticket for self to determine true KVNO. Populating keytab with keys for kvno 1-20");
    // if attempt to retrieve real kvno failed, generate a range of kvno entries 1-20. this hack will not work if password was changed more then 20+ times
    startKvno = 1;
    endKvno = startKvno + 20;
}
else
{
    endKvno = startKvno;
}

var realm = credentials.Domain;
List<KerberosKey> kerberosKeys = new();
foreach (var spn in spns)
{
    foreach (var (encryptionType, salt) in credentials.Salts)
    {
        for(int kvno = startKvno.Value; kvno<=endKvno; kvno++)
        {
            var key = new KerberosKey(password, new PrincipalName(PrincipalNameType.NT_SRV_HST, realm, new[] { spn }), salt: salt, etype: encryptionType, kvno: kvno);
            kerberosKeys.Add(key);
        }

    }
}
foreach (var (encryptionType, salt) in credentials.Salts)
{
    for(int kvno = startKvno.Value; kvno<=endKvno; kvno++)
    {
        var key = new KerberosKey(password, new PrincipalName(PrincipalNameType.NT_PRINCIPAL, realm, new[] { username }), salt: salt, etype: encryptionType, kvno: kvno);
        kerberosKeys.Add(key);
    }
    
}
var keyTable = new KeyTable(kerberosKeys.ToArray());

await using var fs = new FileStream(keytabPath, FileMode.OpenOrCreate);
await using var bw = new BinaryWriter(fs);
keyTable.Write(bw);