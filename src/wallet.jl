
function EtheriumPrivateToAddress(priv::HexString)
    priv = hex2int(priv.value)
    pub = priv*NaiveWallet.G
    x = string(pub.x.v,base=16)
    y = string(pub.y.v,base=16)
    pub_cat = x*y
	# apply etheriums hashing
    addr = KECCAK256(HexString(pub_cat),eth=true)
    return addr[end-39:end]
end

function EtheriumPrivateToAddress(priv::String)
    bytes = [UInt8(c) for c in priv]
    priv =  bytes2int(bytes)
    pub = priv*NaiveWallet.G
    x = string(pub.x.v,base=16)
    y = string(pub.y.v,base=16)
    pub_cat = x*y
    addr = KECCAK256(HexString(pub_cat),eth=true)
    return addr[end-39:end]
end

function EtherScanBalance(addr::HexString,key::String)
	res = HTTP.get("https://api.etherscan.io/api?module=account&action=balance&address=0x$(addr.value)&tag=latest&apikey=$key")
	return BigFloat(1e-18)*parse(BigInt,split(join(Char.(res.body),""),"\"")[end-1])
end
