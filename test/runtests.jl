using Test
my_tests = [
  "test_hash.jl",
  "test_elliptic_curves.jl",
  "test_wallet.jl"
]

println("Running tests:")
for my_test in my_tests
  include(my_test)
end
