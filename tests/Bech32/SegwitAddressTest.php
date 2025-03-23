<?php

namespace BitWasp\Bitcoin\Tests\Bech32;

use BitWasp\Bitcoin\Bech32;
use BitWasp\Bitcoin\Exceptions\Bech32Exception;
use BitWasp\Bitcoin\Tests\Bech32\Provider\InvalidAddresses;
use BitWasp\Bitcoin\Tests\Bech32\Provider\ValidAddresses;
use BitWasp\Bitcoin\Tests\Bech32\Util;
use BitWasp\Bitcoin\Tests\Bech32\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;

class SegwitAddressTest extends TestCase
{
    /**
     * @return array
     */
    public static function validAddressProvider()
    {
        return ValidAddresses::load();
    }

    /**
     * https://github.com/sipa/bech32/blob/master/ref/python/tests.py#L106
     * @param string $hrp
     * @param string $bech32
     * @param string $hexScript
     * @dataProvider validAddressProvider
     */
    #[DataProvider('validAddressProvider')]
    public function testValidAddress($hrp, $bech32, $hexScript)
    {
        list($version, $program) = Bech32::decodeSegwit($hrp, $bech32);
        $this->assertEquals($hexScript, Util::witnessProgram($version, $program));

        $addr = Bech32::encodeSegwit($hrp, $version, $program);
        $this->assertEquals(strtolower($bech32), strtolower($addr));
    }


    public static function invalidAddressProvider()
    {
        return [
            ["tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty"],
            ["bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5"],
            ["BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2"],
            ["bc1rw5uspcuh"],
            ["bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90"],
            ["BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P"],
            ["tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7"],
            ["tb1pw508d6qejxtdg4y5r3zarqfsj6c3"],
            ["tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv"],
        ];
    }

    /**
     * @param string $bech32
     * @dataProvider invalidAddressProvider
     */
    #[DataProvider('invalidAddressProvider')]
    public function testInvalidAddress($bech32)
    {
        try {
            Bech32::decodeSegwit("bc", $bech32);
            $threw = false;
        } catch (\Exception $e) {
            $threw = true;
        }

        $this->assertTrue($threw, "expected mainnet hrp to fail");

        try {
            Bech32::decodeSegwit("tb", $bech32);
            $threw = false;
        } catch (\Exception $e) {
            $threw = true;
        }

        $this->assertTrue($threw, "expected testnet hrp to fail");
    }

    /**
     * @return array
     */
    public static function invalidAddressProvider2()
    {
        return InvalidAddresses::load();
    }

    /**
     * @param $prefix
     * @param $bech32
     * @param $exceptionMsg
     * @dataProvider invalidAddressProvider2
     */
    #[DataProvider('invalidAddressProvider2')]
    public function testInvalidAddressReasons($prefix, $bech32, $exceptionMsg)
    {
        $this->expectException(Bech32Exception::class);
        $this->expectExceptionMessage($exceptionMsg);

        Bech32::decodeSegwit($prefix, $bech32);
    }
}
