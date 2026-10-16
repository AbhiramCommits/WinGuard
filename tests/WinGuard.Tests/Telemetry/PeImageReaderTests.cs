using System.Buffers.Binary;
using System.Text;
using WinGuard.Core.Telemetry;

namespace WinGuard.Tests.Telemetry;

public sealed class PeImageReaderTests
{
    [Fact]
    public void ParsesSyntheticPe32PlusHeaders()
    {
        const ulong imageBase = 0x00007FF6_12340000;
        const uint sizeOfImage = 0x00020000;

        var image = BuildPe32Plus(imageBase, sizeOfImage, textRva: 0x1000, textVirtualSize: 0x4000, textRawSize: 0x2000, textPointerToRawData: 0x400);

        Assert.True(PeImageReader.TryParse(image, out var headers));
        Assert.NotNull(headers);
        Assert.Equal(imageBase, headers!.ImageBase);
        Assert.Equal(sizeOfImage, headers.SizeOfImage);
        Assert.Equal(0x8664, headers.Machine);

        var text = headers.TextSection;
        Assert.NotNull(text);
        Assert.Equal(0x1000u, text!.VirtualAddress);
        Assert.Equal(0x2000u, text.SizeOfRawData);
        Assert.Equal(0x400u, text.PointerToRawData);
    }

    [Fact]
    public void RejectsImagesThatAreNotPeFiles()
    {
        Assert.False(PeImageReader.TryParse(new byte[0x1000], out var headers));
        Assert.Null(headers);

        var notMz = new byte[0x1000];
        notMz[0] = 0x7F;
        notMz[1] = (byte)'E';
        Assert.False(PeImageReader.TryParse(notMz, out _));
    }

    [Fact]
    public void Sha256HexIsStableAndLowercase()
    {
        var data = Encoding.ASCII.GetBytes("WinGuard");
        var hash = PeImageReader.Sha256Hex(data);

        Assert.Equal(64, hash.Length);
        Assert.Equal(hash, hash.ToLowerInvariant());
        Assert.Equal(hash, PeImageReader.Sha256Hex(data));
        Assert.NotEqual(hash, PeImageReader.Sha256Hex(Encoding.ASCII.GetBytes("Winguard")));
    }

    [Fact]
    public void HashesTheOnDiskTextSection()
    {
        const uint rawSize = 0x400;
        const uint pointerToRawData = 0x600;
        var image = BuildPe32Plus(0x00007FF6_12340000, 0x00020000, textRva: 0x1000, textVirtualSize: 0x1000, textRawSize: rawSize, textPointerToRawData: pointerToRawData);

        var path = Path.Combine(Path.GetTempPath(), $"winguard-pe-{Guid.NewGuid():N}.exe");
        File.WriteAllBytes(path, image);

        try
        {
            var expected = PeImageReader.Sha256Hex(image.AsSpan((int)pointerToRawData, (int)rawSize));
            var actual = PeImageReader.HashOnDiskTextSection(path);
            Assert.Equal(expected, actual);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void ReturnsNullForMissingFile()
    {
        Assert.Null(PeImageReader.HashOnDiskTextSection(Path.Combine(Path.GetTempPath(), "does-not-exist.exe")));
    }

    private static byte[] BuildPe32Plus(
        ulong imageBase,
        uint sizeOfImage,
        uint textRva,
        uint textVirtualSize,
        uint textRawSize,
        uint textPointerToRawData)
    {
        const int peOffset = 0x80;
        const int optionalHeaderSize = 0xF0;
        const int sectionTable = peOffset + 4 + 20 + optionalHeaderSize;
        const int sectionHeaderSize = 40;

        var total = Math.Max(sectionTable + sectionHeaderSize, (int)(textPointerToRawData + textRawSize));
        var buffer = new byte[total];

        buffer[0] = (byte)'M';
        buffer[1] = (byte)'Z';
        BinaryPrimitives.WriteInt32LittleEndian(buffer.AsSpan(0x3C), peOffset);
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(peOffset), 0x00004550);

        var coff = peOffset + 4;
        BinaryPrimitives.WriteUInt16LittleEndian(buffer.AsSpan(coff), 0x8664);
        BinaryPrimitives.WriteUInt16LittleEndian(buffer.AsSpan(coff + 2), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(buffer.AsSpan(coff + 16), optionalHeaderSize);

        var optional = coff + 20;
        BinaryPrimitives.WriteUInt16LittleEndian(buffer.AsSpan(optional), 0x20B);
        BinaryPrimitives.WriteUInt64LittleEndian(buffer.AsSpan(optional + 24), imageBase);
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(optional + 56), sizeOfImage);

        Encoding.ASCII.GetBytes(".text").CopyTo(buffer, sectionTable);
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(sectionTable + 8), textVirtualSize);
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(sectionTable + 12), textRva);
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(sectionTable + 16), textRawSize);
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(sectionTable + 20), textPointerToRawData);

        for (var i = 0; i < textRawSize; i++)
        {
            buffer[textPointerToRawData + i] = (byte)(i & 0xFF);
        }

        return buffer;
    }
}
