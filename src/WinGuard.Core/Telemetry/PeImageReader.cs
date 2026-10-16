using System.Buffers.Binary;
using System.Security.Cryptography;

namespace WinGuard.Core.Telemetry;

/// <summary>A section header from a PE image.</summary>
public sealed record PeSection(string Name, uint VirtualAddress, uint VirtualSize, uint SizeOfRawData, uint PointerToRawData);

/// <summary>The header facts WinGuard needs from a PE image.</summary>
public sealed record PeImageHeaders(ushort Machine, ulong ImageBase, uint SizeOfImage, IReadOnlyList<PeSection> Sections)
{
    /// <summary>The <c>.text</c> section, if present.</summary>
    public PeSection? TextSection =>
        Sections.FirstOrDefault(s => string.Equals(s.Name, ".text", StringComparison.Ordinal));
}

/// <summary>
/// Minimal, dependency-free PE/COFF header reader.
/// </summary>
/// <remarks>
/// Parsing is deliberately platform agnostic so it can be unit tested on macOS
/// and Linux with synthetic images even though its production caller
/// (<c>Win32EtwTelemetrySource</c>) is Windows-only. The same code parses the
/// on-disk executable and the in-memory image headers read with
/// <c>ReadProcessMemory</c>, which is what makes the patched-code rule
/// (in-memory .text hash vs on-disk .text hash) an apples-to-apples comparison.
/// </remarks>
public static class PeImageReader
{
    /// <summary>Bytes to probe from the top of an image when looking for headers.</summary>
    public const int HeaderProbeSize = 0x1000;

    private const ushort DosSignature = 0x5A4D;      // "MZ"
    private const uint PeSignature = 0x00004550;      // "PE\0\0"
    private const ushort Pe32Magic = 0x10B;
    private const ushort Pe32PlusMagic = 0x20B;
    private const int SectionHeaderSize = 40;

    public static bool TryParse(ReadOnlySpan<byte> image, out PeImageHeaders? headers)
    {
        headers = null;

        if (image.Length < 0x40 || BinaryPrimitives.ReadUInt16LittleEndian(image) != DosSignature)
        {
            return false;
        }

        var peOffset = BinaryPrimitives.ReadInt32LittleEndian(image[0x3C..]);
        if (peOffset < 0 || peOffset > image.Length - 24)
        {
            return false;
        }

        if (BinaryPrimitives.ReadUInt32LittleEndian(image[peOffset..]) != PeSignature)
        {
            return false;
        }

        var coff = peOffset + 4;
        var machine = BinaryPrimitives.ReadUInt16LittleEndian(image[coff..]);
        var numberOfSections = BinaryPrimitives.ReadUInt16LittleEndian(image[(coff + 2)..]);
        var sizeOfOptionalHeader = BinaryPrimitives.ReadUInt16LittleEndian(image[(coff + 16)..]);

        var optional = coff + 20;
        if (optional + 60 > image.Length)
        {
            return false;
        }

        var magic = BinaryPrimitives.ReadUInt16LittleEndian(image[optional..]);
        ulong imageBase;
        uint sizeOfImage;

        switch (magic)
        {
            case Pe32PlusMagic:
                imageBase = BinaryPrimitives.ReadUInt64LittleEndian(image[(optional + 24)..]);
                sizeOfImage = BinaryPrimitives.ReadUInt32LittleEndian(image[(optional + 56)..]);
                break;
            case Pe32Magic:
                imageBase = BinaryPrimitives.ReadUInt32LittleEndian(image[(optional + 28)..]);
                sizeOfImage = BinaryPrimitives.ReadUInt32LittleEndian(image[(optional + 56)..]);
                break;
            default:
                return false;
        }

        var sectionTable = optional + sizeOfOptionalHeader;
        var sections = new List<PeSection>(numberOfSections);

        for (var i = 0; i < numberOfSections; i++)
        {
            var offset = sectionTable + (i * SectionHeaderSize);
            if (offset < 0 || offset + SectionHeaderSize > image.Length)
            {
                break;
            }

            var raw = image.Slice(offset, SectionHeaderSize);
            var name = System.Text.Encoding.ASCII.GetString(raw[..8]).TrimEnd('\0');

            sections.Add(new PeSection(
                name,
                BinaryPrimitives.ReadUInt32LittleEndian(raw[12..]),
                BinaryPrimitives.ReadUInt32LittleEndian(raw[8..]),
                BinaryPrimitives.ReadUInt32LittleEndian(raw[16..]),
                BinaryPrimitives.ReadUInt32LittleEndian(raw[20..])));
        }

        headers = new PeImageHeaders(machine, imageBase, sizeOfImage, sections);
        return true;
    }

    /// <summary>SHA-256 of <paramref name="data"/> as lowercase hex.</summary>
    public static string Sha256Hex(ReadOnlySpan<byte> data)
        => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    /// <summary>
    /// Hashes the raw <c>.text</c> bytes of an on-disk PE file. Returns
    /// <see langword="null"/> when the file is not a PE image or has no .text
    /// raw data.
    /// </summary>
    public static string? HashOnDiskTextSection(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return null;
        }

        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);

            var probe = new byte[HeaderProbeSize];
            var read = ReadFully(stream, probe);
            if (!TryParse(probe.AsSpan(0, read), out var headers))
            {
                return null;
            }

            var text = headers!.TextSection;
            if (text is null || text.SizeOfRawData == 0 || text.PointerToRawData == 0)
            {
                return null;
            }

            stream.Seek(text.PointerToRawData, SeekOrigin.Begin);
            var buffer = new byte[text.SizeOfRawData];
            var readBytes = ReadFully(stream, buffer);
            return Sha256Hex(buffer.AsSpan(0, readBytes));
        }
        catch (IOException)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static int ReadFully(Stream stream, byte[] buffer)
    {
        var total = 0;
        while (total < buffer.Length)
        {
            var read = stream.Read(buffer, total, buffer.Length - total);
            if (read == 0)
            {
                break;
            }

            total += read;
        }

        return total;
    }
}
