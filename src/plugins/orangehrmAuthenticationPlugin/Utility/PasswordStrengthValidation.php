<?php

/**
 * OrangeHRM is a comprehensive Human Resource Management (HRM) System that captures
 * all the essential functionalities required for any enterprise.
 * Copyright (C) 2006 OrangeHRM Inc., http://www.orangehrm.com
 *
 * OrangeHRM is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.
 *
 * OrangeHRM is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with OrangeHRM.
 * If not, see <https://www.gnu.org/licenses/>.
 */

namespace OrangeHRM\Authentication\Utility;

use OrangeHRM\Authentication\Dto\UserCredential;
use OrangeHRM\Core\Traits\LoggerTrait;
use OrangeHRM\Framework\Services;
use Throwable;
use ZxcvbnPhp\Zxcvbn;

class PasswordStrengthValidation
{
    use LoggerTrait;

    private Zxcvbn $zxcvbn;

    public const VERY_WEAK = 0;
    public const WEAK = 1;
    public const BETTER = 2;
    public const STRONG = 3;
    public const STRONGEST = 4;

    public function __construct()
    {
        $this->zxcvbn = new Zxcvbn();
    }

    /**
     * @param UserCredential $credential
     * @return int
     */
    public function checkPasswordStrength(UserCredential $credential): int
    {
        //Add if condition in case of library change
        try {
            $strength =  $this->zxcvbn->passwordStrength($credential->getPassword());
            if ($strength['score'] == 0) {
                return self::VERY_WEAK;
            }
            if ($strength['score'] == 1) {
                return self::WEAK;
            }
            if ($strength['score'] == 2) {
                return self::BETTER;
            }
            if ($strength['score'] == 3) {
                return self::STRONG;
            }
            if ($strength['score'] == 4) {
                return self::STRONGEST;
            }
        } catch (Throwable $e) {
            // Also used by the installer CLI, where the logger service isn't available
            if ($this->getContainer()->has(Services::LOGGER)) {
                $this->getLogger()->error('Password strength evaluation failed: ' . $e->getMessage());
                $this->getLogger()->error($e->getTraceAsString());
            }
        }
        return self::VERY_WEAK;
    }
}
