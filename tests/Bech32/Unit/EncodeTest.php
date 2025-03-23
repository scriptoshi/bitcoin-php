<?php

namespace BitWasp\Bitcoin\Tests\Bech32\Unit\Bech32;

use BitWasp\Bitcoin\Tests\Bech32\Provider\ValidAddresses;
use BitWasp\Bitcoin\Tests\Bech32\TestCase;
use BitWasp\Bitcoin\Tests\Bech32\Util;
use BitWasp\Bitcoin\Bech32;
use PHPUnit\Framework\Attributes\DataProvider;

class EncodeTest extends TestCase
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
        // Check we decode, and that HRP matches test fixture
        list($gotHRP, $data) = Bech32::decode($bech32);
        $this->assertEquals($hrp, $gotHRP);

        $decoded = Bech32::convertBits(array_slice($data, 1), count($data) - 1, 5, 8, false);
        $program = '';
        foreach ($decoded as $char) {
            $program .= chr($char);
        }

        // Check decoded details against our known witness program
        $version = $data[0];
        $checkWitnessProgram = Util::witnessProgram($version, $program);
        $this->assertEquals($hexScript, $checkWitnessProgram);

        // Simple re-encoding test

        $encoded = Bech32::encode($hrp, $data);
        $this->assertEquals(strtolower($bech32), $encoded);
    }
}
