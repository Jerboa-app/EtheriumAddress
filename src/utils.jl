function bytes2bits(x::Vector{UInt8})
    b = reverse(x)
    bits = ""
    for d in reverse(b)
        l = bitstring(d)
        while length(l) < 8
            l = "0"*l
        end
        bits *= l
    end
    return bits
end

function bits2int(bits::String)
    n = BigInt(0)
    for (d,i) in enumerate(reverse(bits))
        if i == '1'
            n += BigInt(2)^BigInt(d-1)
        end
    end

    return n
end

function bytes2int(x::Vector{UInt8})
    bits = bytes2bits(x)
    n = BigInt(0)
    for (d,i) in enumerate(reverse(bits))
        if i == '1'
            n += BigInt(2)^BigInt(d-1)
        end
    end

    return n
end

function hex2int(x::String)::BigInt
    if length(x) % 2 != 0
	x = "0"*x
    end
    return bytes2int(hex2bytes(x))
end

function bits2bytes(k)
    bytes = Array{UInt8,1}()
    for i in 1:8:length(k)
        bits = join(Int.(k[i:(i+7)]),"")
        bits = reverse(bits)
        push!(bytes,UInt8(bits2int(bits)))
    end
    return bytes
end

function hex2byte(x::UInt8)
    bits = string(x,base=2)
    while length(bits) < 8
        bits = "0"*bits
    end
    return [parse(Int,b) for b in bits]
end

function hex2bits(x::String)
    bytes = hex2bytes(x)
    bits = ""
    for byte in bytes
        b = string(byte,base=2)
        while length(b) < 8
            b = "0"*b
        end
        bits *= reverse(b)
    end
    return [parse(Int,b) for b in bits]
end
