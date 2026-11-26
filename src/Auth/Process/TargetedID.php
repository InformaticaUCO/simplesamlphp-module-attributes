<?php

declare(strict_types=1);

namespace SimpleSAML\Module\hubandspoke\Auth\Process;

use Exception;
use SAML2\Constants;
use SAML2\XML\saml\NameID;
use SimpleSAML\Auth\ProcessingFilter;
use SimpleSAML\Logger;

/**
 * Filter to generate the eduPersonTargetedID attribute for Hub & Spoke federations.
 *
 * Ported to SimpleSAMLphp 2.x / PHP 8.2+ preserving the exact hash formula of
 * mimaen/simplesamlphp-module-hubandspoke (sha256 over salt@@userID@@targetID@@sourceID@@salt).
 *
 * @author Miguel Macías, UPV (original 1.x)
 */
class TargetedID extends ProcessingFilter
{
    /**
     * Default values for every switch configuring the attribute.
     *
     * @var array<string, mixed>
     */
    private array $defaults = [
        'userID' => 'UserID',
        'ifUser' => null,
        'targetID' => ['saml:RequesterID', 'core:SP'],
        'targetTransform' => null,
        'ifTarget' => null,
        'sourceID' => ['Attributes/schacHomeOrganization', 'core:IdP'],
        'salt' => null,
        'hashFunction' => 'sha256',
        'fields' => ['salt', 'userID', 'targetID', 'sourceID', 'salt'],
        'fieldSeparator' => '@@',
        'prefix' => null,
        'nameId' => false,
    ];

    /**
     * Configuration for the values to be generated.
     *
     * @var array<string, array<string, mixed>>
     */
    private array $confValues = [];

    /**
     * Initialize this filter.
     *
     * @param array<string, mixed> &$config Configuration information about this filter.
     * @param mixed $reserved For future use.
     */
    public function __construct(array &$config, $reserved)
    {
        parent::__construct($config, $reserved);

        if (!array_key_exists('values', $config)) {
            $config['values'] = ['default' => []];
        }

        foreach ($config['values'] as $name => $parameters) {
            $merged = array_merge($this->defaults, $config, (array) $parameters);
            $this->confValues[(string) $name] = $merged;

            $hashAlg = $merged['hashFunction'];
            if (!empty($hashAlg) && !in_array($hashAlg, hash_algos(), true)) {
                throw new Exception('eduPersonTargetedId: hash algorithm (' . $hashAlg . ') not supported');
            }
        }
    }

    /**
     * Apply filter to add the targeted ID.
     *
     * @param array<string, mixed> &$state The current state.
     */
    public function process(array &$state): void
    {
        if (!array_key_exists('Attributes', $state) || !is_array($state['Attributes'])) {
            throw new Exception('eduPersonTargetedId: missing Attributes in state');
        }

        $state['Attributes']['eduPersonTargetedID'] = [];

        foreach ($this->confValues as $name => $parameters) {
            $dataRetrieved = [];

            // Get the identifier of the authenticated user (mandatory)
            $data = empty($parameters['userID'])
                ? ''
                : self::getValue($state, (array) $parameters['userID'], 'eduPersonTargetedId: not user id found');

            if (!empty($parameters['ifUser']) && !self::someMatch($data, (array) $parameters['ifUser'])) {
                Logger::debug('eduPersonTargetedId, ' . $name . ' skipped: userID = ' . $data);
                continue;
            }
            $dataRetrieved['userID'] = $data;

            // Get the identifier of the destination (optional)
            $data = empty($parameters['targetID'])
                ? ''
                : self::getValue($state, (array) $parameters['targetID'], null);

            if (is_array($parameters['targetTransform'])) {
                foreach ($parameters['targetTransform'] as $pattern => $replacement) {
                    $replaced = preg_replace((string) $pattern, (string) $replacement, $data);
                    if ($replaced !== null) {
                        $data = $replaced;
                    }
                }
            }

            if (!empty($parameters['ifTarget']) && !self::someMatch($data, (array) $parameters['ifTarget'])) {
                Logger::debug('eduPersonTargetedId, ' . $name . ' skipped: targetID = ' . $data);
                continue;
            }
            $dataRetrieved['targetID'] = $data;

            // Get the identifier of the source (optional)
            $data = empty($parameters['sourceID'])
                ? ''
                : self::getValue($state, (array) $parameters['sourceID'], null);
            $dataRetrieved['sourceID'] = $data;

            // Salt for obfuscating the hash
            $dataRetrieved['salt'] = empty($parameters['salt']) ? '' : (string) $parameters['salt'];

            // Generate the value applying the hash function
            $dataRaw = [];
            foreach ((array) $parameters['fields'] as $field) {
                $fieldValue = $dataRetrieved[$field] ?? '';
                if (!empty($fieldValue)) {
                    $dataRaw[] = $fieldValue;
                }
            }

            $rawString = implode((string) $parameters['fieldSeparator'], $dataRaw);
            $eduPersonTargetedId = hash((string) $parameters['hashFunction'], $rawString);

            if (!empty($parameters['prefix'])) {
                $eduPersonTargetedId = (string) $parameters['prefix'] . $eduPersonTargetedId;
            }

            $logFields = [];
            foreach ((array) $parameters['fields'] as $field) {
                $fieldValue = $dataRetrieved[$field] ?? '';
                if (!empty($fieldValue)) {
                    $logFields[] = ($field === 'salt') ? '[REDACTED]' : $fieldValue;
                }
            }
            Logger::debug(
                'eduPersonTargetedId, ' . $name . ' function: '
                . $parameters['hashFunction'] . '(' . implode((string) $parameters['fieldSeparator'], $logFields) . ')'
            );
            Logger::debug('eduPersonTargetedId, ' . $name . ' value: ' . $eduPersonTargetedId);

            if (!empty($parameters['nameId'])) {
                $state['Attributes']['eduPersonTargetedID'][] = self::toNameId(
                    $eduPersonTargetedId,
                    $dataRetrieved['sourceID'],
                    $dataRetrieved['targetID']
                );
            } else {
                $state['Attributes']['eduPersonTargetedID'][] = $eduPersonTargetedId;
            }
        }
    }

    /**
     * Get a value from a set of alternative options (in order of preference).
     *
     * @param array<string, mixed> &$state
     * @param array<int, string> $options
     */
    private static function getValue(array &$state, array $options, ?string $error): string
    {
        $value = '';
        foreach ($options as $attributeName) {
            // Separate with / to enter next level (e.g. Attributes/uid => $state['Attributes']['uid'])
            $parts = explode('/', (string) $attributeName . '/');
            $level1 = $parts[0];
            $level2 = $parts[1] ?? '';

            if (array_key_exists($level1, $state)) {
                $data = $state[$level1];
                if ($level2 !== '') {
                    if (is_array($data) && array_key_exists($level2, $data)) {
                        $data = $data[$level2];
                    } else {
                        $data = null;
                    }
                }
                if (!empty($data)) {
                    $data = (array) $data;
                    $value = (string) $data[0];
                    break;
                }
            }
        }

        if ($value === '' && $error !== null && $error !== '') {
            throw new Exception($error);
        }

        return $value;
    }

    /**
     * Check that a string matches one or more regular expressions.
     *
     * @param array<int, string> $listRegExp
     */
    private static function someMatch(string $value, array $listRegExp): bool
    {
        foreach ($listRegExp as $regExp) {
            if (preg_match((string) $regExp, $value) === 1) {
                return true;
            }
        }

        return false;
    }

    /**
     * Convert the targeted ID to a SAML 2.0 NameID object.
     */
    private static function toNameId(string $value, string $source, string $destination): NameID
    {
        $nameId = new NameID();
        $nameId->setFormat(Constants::NAMEID_PERSISTENT);
        $nameId->setValue($value);

        if ($source !== '') {
            $nameId->setNameQualifier($source);
        }
        if ($destination !== '') {
            $nameId->setSPNameQualifier($destination);
        }

        return $nameId;
    }
}
