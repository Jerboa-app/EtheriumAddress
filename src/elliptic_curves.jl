import Base: +,-,*,/,^,inv,==

struct FieldElement
    v::BigInt # a value
    p::BigInt # the modulus of the field
end

function FieldElement(x::Union{BigInt,Int})
    return FieldElement(x,secp256k1P)
end

# all follow the structure op(p,q) := op(p.v,q.v) % *field modulus*
+(p::FieldElement,q::FieldElement) = FieldElement( mod((p.v+q.v) , p.p),p.p)
-(p::FieldElement,q::FieldElement) = FieldElement( mod((p.v-q.v) , p.p),p.p)
*(p::FieldElement,q::FieldElement) = FieldElement( mod((p.v*q.v), p.p),p.p)
*(v::T,q::FieldElement) where {T<:Number} = FieldElement( mod((v*q.v) , q.p),q.p)
*(q::FieldElement,v::T) where {T<:Number} = *(v,q)
# int and bigint powers
^(p::FieldElement,v::BigInt) = FieldElement( mod((p.v^v) , p.p),p.p)
# needs to promote big int to avoid overflows
^(p::FieldElement,v::Int) = ^(p,BigInt(v))
inv(p::FieldElement) = invmod(p.v,p.p) # Take the inverse of x modulo m: y such that $x y = 1 \pmod m$, with $div(x,y) = 0$. This is undefined for $m = 0$, or if $gcd(x,m) \neq 1$.
# careful to use invmod not / !
/(p::FieldElement,q::FieldElement) = FieldElement( mod((p*inv(q)).v , p.p),p.p)

# equality means p-q is the zero element!
==(p::FieldElement,q::FieldElement) = (p-q).v == 0 ? true : false

abstract type EllipticCurvePoint end

# particular constants
const secp256k1P = hex2int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
const secp256k1G = (hex2int("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),hex2int("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"))
const secp256k1N = hex2int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")

struct secp256k1Point
    x::Union{Nothing,FieldElement}
    y::Union{Nothing,FieldElement}
end

function secp256k1Point(x::Int,y::Int)
    return secp256k1Point(FieldElement(mod(x,secp256k1P),secp256k1P),FieldElement(mod(y,secp256k1P),secp256k1P))
end

function secp256k1Point(x::BigInt,y::BigInt)
    return secp256k1Point(FieldElement(mod(x,secp256k1P),secp256k1P),FieldElement(mod(y,secp256k1P),secp256k1P))
end

# should satisfy the equation
function validPoint(p::secp256k1Point)
    if p == I
        return true
    end
    return (p.y^2 - p.x^3 - FieldElement(7,secp256k1P)).v == 0
end

# infinite
const I = secp256k1Point(nothing,nothing)
const G = secp256k1Point(secp256k1G...)

==(p::secp256k1Point,q::secp256k1Point) = (p.x==q.x) && (p.y==q.y)

function +(p::secp256k1Point,q::secp256k1Point)

    # handle infs
    if p==I
        return q
    elseif q==I
        return p
    end

    # handle inverse on y coord
    if p.x == q.x && p.y == (-1*q.y)
        return I
    end

    # avoid div by zero
    if p.x != q.x
        s = (q.y-p.y) / (q.x-p.x)
        x = s^2 - p.x - q.x
        y = s*(p.x-x)-p.y

        return secp256k1Point(x,y)
    end

    # another inf
    if p == q && p.y == nothing
        return I
    end

    # multiples
    if p == q
        s = (3*(p.x^2)) / (2*p.y)
        x = s^2 - 2*p.x
        y = s*(p.x-x)-p.y

        return secp256k1Point(x,y)
    end

    return I
end

# multiplication in an efficient manner
function *(v::Union{Int,BigInt},p::secp256k1Point)
    c = p
    res = I
    while v > 0
        if (v & 1) == true
            res = res + c
        end
        c = c + c
        v >>= 1
    end
    return res
end
