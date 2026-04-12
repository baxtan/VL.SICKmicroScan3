using System.Buffers.Binary;

namespace Main;

public sealed class ScanFragment
{
    public uint Identification { get; init; }
    public uint TotalLength { get; init; }
    public uint FragmentOffset { get; init; }
    public byte[] Payload { get; init; } // bytes [24..end] of UDP datagram
}

public sealed class ScanAssembly
{
    public uint Identification { get; }
    public byte[] Buffer { get; }
    public int BytesReceived { get; private set; }
    public bool IsComplete => BytesReceived == Buffer.Length;
    public DateTime LastUpdated { get; private set; }

    public ScanAssembly(uint identification, uint totalLength)
    {
        Identification = identification;
        Buffer = new byte[totalLength];
        LastUpdated = DateTime.UtcNow;
    }

    public void AddFragment(ScanFragment fragment)
    {
        int destOffset = (int)fragment.FragmentOffset;
        int copyLength = fragment.Payload.Length;

        System.Buffer.BlockCopy(
            fragment.Payload, 0,
            Buffer, destOffset,
            copyLength);

        BytesReceived += copyLength;
        LastUpdated = DateTime.UtcNow;
    }
}

[ProcessNode]
public class ScanReassembler
{
    private readonly Dictionary<uint, ScanAssembly> _assemblies = new();
    private readonly TimeSpan _timeout = TimeSpan.FromMilliseconds(500);
    private byte[] _completedScan = Array.Empty<byte>();

    public void Update(
        IReadOnlyList<byte> udpDatagram,
        out bool scanReady,
        out Spread<byte> completedPayload)
    {
        scanReady = false;
        completedPayload = Spread<byte>.Empty;

        if (udpDatagram.Count < 24)
            return;

        var buf = udpDatagram.ToArray();

        // Parse the 24-byte SICK fragment header
        uint totalLength = BinaryPrimitives.ReadUInt32LittleEndian(buf.AsSpan(8, 4));
        uint identification = BinaryPrimitives.ReadUInt32LittleEndian(buf.AsSpan(12, 4));
        uint fragOffset = BinaryPrimitives.ReadUInt32LittleEndian(buf.AsSpan(16, 4));

        // Strip header → payload
        var fragment = new ScanFragment
        {
            Identification = identification,
            TotalLength = totalLength,
            FragmentOffset = fragOffset,
            Payload = buf[24..]
        };

        // Evict stale assemblies
        var stale = _assemblies
            .Where(kv => DateTime.UtcNow - kv.Value.LastUpdated > _timeout)
            .Select(kv => kv.Key)
            .ToList();
        foreach (var id in stale)
            _assemblies.Remove(id);

        // Get or create assembly for this ID
        if (!_assemblies.TryGetValue(identification, out var assembly))
        {
            assembly = new ScanAssembly(identification, totalLength);
            _assemblies[identification] = assembly;
        }

        assembly.AddFragment(fragment);

        if (assembly.IsComplete)
        {
            _completedScan = assembly.Buffer;
            _assemblies.Remove(identification);
            scanReady = true;
            completedPayload = _completedScan.ToSpread();
        }
    }
}  