<?php

declare(strict_types=1);

namespace BitWasp\Bitcoin\Tests\Serializer\Key\HierarchicalKey;

use BitWasp\Bitcoin\Crypto\EcAdapter\Adapter\EcAdapterInterface;
use BitWasp\Bitcoin\Network\NetworkFactory;
use BitWasp\Bitcoin\Serializer\Key\HierarchicalKey\ExtendedKeySerializer;
use BitWasp\Bitcoin\Tests\AbstractTestCase;
use BitWasp\Buffertools\Buffer;
use PHPUnit\Framework\Attributes\DataProvider;

class ExtendedKeySerializerTest extends AbstractTestCase
{
    /**
     * @dataProvider getEcAdapters
     * @param EcAdapterInterface $adapter
     */
    #[DataProvider('getEcAdapters')]
    public function testInvalidKey(EcAdapterInterface $adapter)
    {
        $this->expectException(\BitWasp\Buffertools\Exceptions\ParserOutOfRange::class);
        $network = NetworkFactory::bitcoinTestnet();
        $serializer = new ExtendedKeySerializer($adapter);
        $serializer->parse($network, new Buffer());
    }
}
