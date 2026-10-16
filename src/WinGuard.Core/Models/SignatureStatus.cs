namespace WinGuard.Core.Models;

/// <summary>
/// Authenticity of a module (DLL / driver) image as reported by the Windows
/// subject-interface package (Authenticode via <c>WinVerifyTrust</c>).
/// </summary>
public enum SignatureStatus
{
    /// <summary>Authenticode could not be evaluated (missing file, access denied, unsupported format).</summary>
    Unknown = 0,

    /// <summary>No embedded signature, or the signature is present but not valid.</summary>
    Unsigned = 1,

    /// <summary>Signed, but chained to an untrusted / self-issued root (not in the machine store).</summary>
    SelfSigned = 2,

    /// <summary>Signature verified against a trusted root (Microsoft, WHQL, a trusted publisher CA).</summary>
    Signed = 3,
}
