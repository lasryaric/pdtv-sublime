<?php

namespace Producteev\CoreBundle\Service;

use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\Translation\Translator;
use Producteev\CoreBundle\Manager\UserManager;
use Producteev\CoreBundle\Document\User;
use Producteev\CoreBundle\Document\Project;
use Producteev\CoreBundle\Document\File;
use Producteev\CoreBundle\Document\Network;
use Producteev\CoreBundle\Utils\StrCleaner;
use Producteev\CoreBundle\Exception\InputInvalidException;
use Producteev\CoreBundle\Exception\IntegrityConstraintException;
use Producteev\CoreBundle\Service\AvatarService;
use Producteev\CoreBundle\Event\UserEvent;
use Producteev\CoreBundle\Utils\EmailManager;
use Symfony\Bundle\FrameworkBundle\Routing\Router;
use Producteev\CoreBundle\Privacy\ProjectPrivacy;
use Predis\Client as RedisClient;
use Producteev\CoreBundle\Utils\StrSearch as StrSearchUtil;
use Producteev\CoreBundle\Service\NetworkService;

class UserService extends ProducteevBaseService
{
    private $avatarService;
    private $eventDispatcher;
    private $emailManager;
    private $redisClient;
    private $pwdRedisKeyLifetime;
    private $strSearchUtil;
    private $verificationTokenLifetime;

    const EMAIL_CATEGORY_RESET_PASSWORD_REQUEST = "user.resetpasswordrequest.passwordtoken";
    const EMAIL_TEMPLATE_RESET_PASSWORD_REQUEST = "email.user.resetpasswordrequest";

    const PASSWORD_TOKEN_REDIS_KEY_PREFIX = "useraccount_passwordtoken_";
    const VERIFICATION_TOKEN_REDIS_KEY_PREFIX = "useraccount_veriftoken_";

    const EMAIL_CATEGORY_RESET_PASSWORD_CONFIRMATION = "user.resetpassword.confirmation";
    const EMAIL_TEMPLATE_RESET_PASSWORD_CONFIRMATION = "email.user.resetpasswordconfirmation";

    public function __construct(UserManager $userManager, AvatarService $avatarService,
        EventDispatcher $eventDispatcher, EmailManager $emailManager, Translator $translator, RedisClient $redisClient, $pwdTokenRedisKeyLifetime,
        Router $router, ProjectPrivacy $projectPrivacy, StrSearchUtil $strSearchUtil, $verificationTokenLifetime, NetworkService $networkService)
    {
        parent::__construct($userManager);
        $this->avatarService = $avatarService;
        $this->eventDispatcher = $eventDispatcher;
        $this->emailManager = $emailManager;
        $this->translator = $translator;
        $this->redisClient = $redisClient;
        $this->pwdTokenRedisKeyLifetime = $pwdTokenRedisKeyLifetime;
        $this->router = $router;
        $this->projectPrivacy = $projectPrivacy;
        $this->strSearchUtil = $strSearchUtil;
        $this->verificationTokenLifetime = $verificationTokenLifetime;
        $this->networkService = $networkService;
    }

    /**
     * Signup a new user
     *
     * @param string $email
     * @param string $password
     * @param string $firstname
     * @param string $lastname
     * @param optional string $timezone
     * @param optional string $jobTitle
     * @param optional string $ipAddress
     * @return User $user
     */
    public function signup($email, $password, $firstname, $lastname, $timezone = "UTC", $jobTitle = null, $ipAddress = null)
    {
        $user = $this->createUser($email, $firstname, $lastname, $timezone, $jobTitle, $ipAddress);
        $this->objectManager->setPassword($password, $user);
        $this->objectManager->persist($user);

        //Send an email to the user to verified is account
        $this->sendVerificationEmail($user, true);

        $event = new UserEvent($user);
        $this->eventDispatcher->dispatch(UserEvent::SIGNUP, $event);

        return $user;
    }

    /**
     * Signup a facebook new user
     *
     * @param string $email
     * @param string $firstname
     * @param string $lastname
     * @param string $facebookId
     * @param optional string $timezone
     * @return User $user
     */
    public function signupFacebookUser($email, $firstname, $lastname, $facebookId, $timezone = "UTC", $jobTitle = null, $ipAddress = null)
    {
        $user = $this->createUser($email, $firstname, $lastname, $timezone, $jobTitle, $ipAddress);
        $this->objectManager->setFacebookId($user, $facebookId);
        //Facebook user is verified by facebook authentication process
        $this->objectManager->switchToVerified($user);
        $this->objectManager->persist($user);
        $event = new UserEvent($user);
        $this->eventDispatcher->dispatch(UserEvent::SIGNUP, $event);

        return $user;
    }

    /**
     * Create a new user
     *
     * @param string $email
     * @param string $firstname
     * @param string $lastname
     * @param optional string $timezone
     * @return User $user
     */
    private function createUser($email, $firstname, $lastname, $timezone = "UTC", $jobTitle = null, $ipAddress = null)
    {
        $user = $this->objectManager->create();
        $this->objectManager->setEmail($user, $email);
        $this->objectManager->setName($user, $firstname, $lastname);
        $this->objectManager->setTimezone($user, $timezone);
        $this->objectManager->setJobTitle($user, $jobTitle);
        $this->objectManager->setIpAddress($user, $ipAddress);

        return $user;
    }

    /**
    * Set $email for the $user
    *
    * @param string $email
    * @param Model\User $user
    * @return User $user
    */
    public function setEmail($email, User $user)
    {
        $this->objectManager->setEmail($user, $email);
        $this->objectManager->persist($user);

        return $user;
    }

    /**
    * Set the $password for the $user
    *
    * @param string $password
    * @param Model\User $user
    * @return User $user
    */
    public function setPassword($password, User $user)
    {
        $this->objectManager->setPassword($password, $user);
        $this->objectManager->persist($user);

        return $user;
    }

    /**
    * Set the v3 hash as password for the $user
    *
    * @param string $hash
    * @param Model\User $user
    * @return User $user
    */
    public function setV3Password($hash, User $user)
    {
        $this->objectManager->setV3Password($hash, $user);
        $this->objectManager->persist($user);

        return $user;
    }

    /**
     * Set user's name
     *
     * @param User $user
     * @param string $firstname
     * @param string $lastname
     * @return User $user
     */
    public function setName(User $user, $firstname, $lastname)
    {
        $this->objectManager->setName($user, $firstname, $lastname);
        $this->objectManager->persist($user);

        return $user;
    }

    /**
     * Set user firstname
     *
     * @param User $user
     * @param string $firstname
     * @return User $user
     */
    public function setFirstname(User $user, $firstname)
    {
        $this->objectManager->setFirstname($user, $firstname);
        $this->objectManager->persist($user);

        return $user;
    }

    /**
     * Set user lastname
     *
     * @param User $user
     * @param string $lastname
     * @return User $user
     */
    public function setLastname(User $user, $lastname)
    {
        $this->objectManager->setLastname($user, $lastname);
        $this->objectManager->persist($user);

        return $user;
    }

    /**
     * Set an avatar for a user
     *
     * @param User $user
     * @param string $localPath avatar file on the local file system
     * @return User $user
     */
    public function setAvatar(User $user, $localPath)
    {
        $hashAvatar = $this->avatarService->set($user, $localPath);
        $this->objectManager->setAvatar($user, $hashAvatar);
        $this->objectManager->persist($user);

        return $user;
    }

    /**
     * Clear the user avatar
     *
     * @param User $user
     * @return User $user
     */
    public function clearAvatar(User $user)
    {
        $this->objectManager->setAvatar($user, null);
        $this->objectManager->persist($user);

        return $user;
    }

    /**
     * Set an avatar for a user from a remote url
     *
     * @param User $user
     * @param string $url avatar file remote url
     * @return User $user
     */
    public function setAvatarFromRemoteUrl(User $user, $url)
    {
        if(!mb_strlen($url)) {
            throw new InputInvalidException($this->translator->trans("core.inputinvalidexception.remotefile_no_url"));
        }
        $hashAvatar = $this->avatarService->setRemoteFile($user, $url);
        $this->objectManager->setAvatar($user, $hashAvatar);
        $this->objectManager->persist($user);

        return $user;
    }

    /**
     * Set the timezone for a user
     *
     * @param User $user
     * @param string $timezone
     * @return User $user
     */
    public function setTimezone(User $user, $timezone)
    {
        $this->objectManager->setTimezone($user, $timezone);
        $this->objectManager->persist($user);

        return $user;
    }


    /**
     * Set the $user jobTitle
     *
     * @param User $user
     * @param string $jobTitle
     * @return User $user
     */
    public function setJobTitle(User $user, $jobTitle)
    {
        $this->objectManager->setJobTitle($user, $jobTitle);
        $this->objectManager->persist($user);

        return $user;
    }

    /**
    * Find a user by his id, with the right of the $user
    *
    * @param User $user
    * @param string $id
    * @return User $user
    * @todo handle privacy
    */
    public function findOneById(User $user, $id)
    {
        $user = $this->objectManager->findOneById($id);

        return $user;
    }


    /**
    * Check if the $email is already attached to a user
    *
    * @param string $email
    * @return bool
    */
    public function checkEmailExists($email)
    {
        $user = $this->objectManager->findOneByEmail($email);

        return ($user !== null);
    }

    /**
    * Generate a new password token and send an email
    *
    * @param String $email
    * @return User $user
    */
    public function requestPasswordReset($email)
    {
        //Get the user by email address
        $user = $this->objectManager->findOneByEmail($email);
        if ($user == null) {
            throw new InputInvalidException($this->translator->trans("core.inputinvalidexception.unknown_email_address", array("%email%" => $email)));
        }

        //generate a new password token and save it
        $this->objectManager->generateNewPasswordToken($user);
        $this->objectManager->persist($user);

        //Save the key in redis with an expiration time
        $redisKey = $this->getPasswordTokenRedisKey($user->getLastPasswordToken());
        $this->redisClient->set($redisKey, $user->getId());
        $expiration = $this->pwdTokenRedisKeyLifetime;
        $this->redisClient->expire($redisKey, $expiration);

        //Send an email with the token
        $this->sendRequestPasswordResetEmail($user);

        return $user;
    }

    /**
    * Send an email to the user with the password token inside
    *
    * @param User $user
    */
    private function sendRequestPasswordResetEmail(User $user)
    {
        $recipient = $user->getEmail();
        $subject = $this->translator->trans("email.useraccount.resetpasswordrequest_subject");
        $template = self::EMAIL_TEMPLATE_RESET_PASSWORD_REQUEST;
        $token = $user->getLastPasswordToken();
        $urlParams = Array(
            "backboneroutes" => sprintf("%s/%s", $recipient, $token)
        );
        $reset_url = $this->router->generate("producteev_web_reset_password", $urlParams, true);
        $params = array("token" => $token, "reset_url" => $reset_url, "fullname" => $user->getFullname());
        $categories = array(self::EMAIL_CATEGORY_RESET_PASSWORD_REQUEST);
        $this->emailManager->prepareAndSend($recipient, $subject, $template, $params, $categories);
    }

    /**
    * Change the user password if the passwordToken is valid and if the newPassword respect rules and equals confirmation
    *
    * @param String $email
    * @param String $passwordToken
    * @param String $newPassword
    * @param String $newPasswordConfirmation
    * @return User $user
    */
    public function resetPassword($email, $passwordToken, $newPassword, $newPasswordConfirmation)
    {
        //Check if the newPassword and the passwordConfirmation are equals
        if ($newPassword != $newPasswordConfirmation) {
            throw new InputInvalidException($this->translator->trans("core.inputinvalidexception.password_and_confirmation_not_equals"));
        }

        //Get the user by email address
        $user = $this->objectManager->findOneByEmail($email);
        if ($user == null) {
            throw new InputInvalidException($this->translator->trans("core.inputinvalidexception.unknown_email_address", array("%email%" => $email)));
        }

        // check if the password token is valid by checking in redis store
        $redisKey = $this->getPasswordTokenRedisKey($passwordToken);
        if ($this->redisClient->get($redisKey) != $user->getId()) {
            throw new InputInvalidException($this->translator->trans("core.inputinvalidexception.password_reset_unvalid_token"));
        }

        //set the new password and save it
        $this->objectManager->setPassword($newPassword, $user);
        $this->objectManager->persist($user);

        //Remove the key in redis
        $this->redisClient->del($redisKey);

        //send an email to notify its password has changed
        $this->sendPasswordResetConfirmationEmail($user);

        return $user;
    }

    /**
    * Send a confirmation email to the user saying that is password has changed
    *
    * @param User $user
    */
    private function sendPasswordResetConfirmationEmail(User $user)
    {
        $recipient = $user->getEmail();
        $subject = $this->translator->trans("email.useraccount.resetpasswordconfirmation_subject");
        $params = array("user" => $user);
        $categories = array(self::EMAIL_CATEGORY_RESET_PASSWORD_CONFIRMATION);
        $template = self::EMAIL_TEMPLATE_RESET_PASSWORD_CONFIRMATION;
        $this->emailManager->prepareAndSend($recipient, $subject, $template, $params, $categories);
    }

    public function getPasswordTokenRedisKey($passwordToken)
    {
        $redisKey = sprintf("%s%s", self::PASSWORD_TOKEN_REDIS_KEY_PREFIX, $passwordToken);

        return $redisKey;
    }

    /**
    * Change the user password
    *
    * @param User $user
    * @param String $oldPassword
    * @param String $newPassword
    * @param String $newPasswordConfirmation
    * @return User $user
    */
    public function changePassword(User $user, $oldPassword, $newPassword, $newPasswordConfirmation)
    {
        $encodedOldPassword = $this->objectManager->encodePassword($user, $oldPassword);

        if ($encodedOldPassword != $user->getPassword()) {
            throw new InputInvalidException($this->translator->trans("core.inputinvalidexception.change_password_old_password_invalid"));
        }
        if ($newPassword != $newPasswordConfirmation) {
            throw new InputInvalidException($this->translator->trans("core.inputinvalidexception.password_and_confirmation_different"));
        }
        $this->setPassword($newPassword, $user);

        return $user;
    }

    /**
    * Set the facebook id for the user
    *
    * @param User $user
    */
    public function setFacebookId(User $user, $facebookId)
    {
        $this->objectManager->setFacebookId($user, $facebookId);
        $this->objectManager->persist($user);

        return $user;
    }

    /**
     * Set the google id for the $user
     *
     * @param User $user
     * @param string googleId
     * @return User $user
     */
    public function setGoogleId(User $user, $googleId)
    {
        $this->objectManager->setGoogleId($user, $googleId);
        $this->objectManager->persist($user);

        return $user;
    }

    /**
    * Get a user by its facebook id
    *
    * @param User $user
    * @param String $facebookId
    * @return User $fbUser
    * @todo implement privacy
    */
    public function getUserByFacebookId($facebookId)
    {
        $fbUser = $this->objectManager->findOneByFacebookId($facebookId);

        return $fbUser;
    }

    /**
    * Get a user by its google id
    *
    * @param User $user
    * @param String $googleId
    * @return User $googleUser
    * @todo implement privacy
    */
    public function getUserByGoogleId($googleId)
    {
        $googleUser = $this->objectManager->findOneByGoogleId($googleId);

        return $googleUser;
    }

    /**
    * Set the default project a $user
    *
    * @param User $user
    * @param Project $defaultProject
    * @return User $user
    */
    public function setDefaultProject(User $user, Project $defaultProject)
    {
        $this->projectPrivacy->assertCanView($user, $defaultProject);
        $this->objectManager->setDefaultProject($user, $defaultProject);
        $this->objectManager->persist($user);

        return $user;
    }

    /**
     * Search users matching $search in $network (using the ngram method)
     *
     * @param User $user
     * @param Network $network
     * @param String $search
     * @param integer $limit
     * @return array<User> $usersFound
     */
    public function searchUsersForNetwork(User $user, Network $network, $search, $limit = null, User $excludeUser = null)
    {
        $users = $network->getUsers();
        $usersFound = array();
        $i = 0;
        foreach ($users as $user) {
            if ($this->strSearchUtil->ngram($search, $user->getFullname()) && ($excludeUser === null || $user->getId() !== $excludeUser->getId())) {
                $usersFound[ ] = $user;
                if ($limit !== null && $i >= $limit-1) {
                    break;
                }
                $i++;
            }
        }

        return $usersFound;
    }

    /**
     * Find users with $fullname beginning with $search in $network
     * Used by NlpUserParser
     *
     * @param User $user
     * @param Network $network
     * @param String $search
     * @return array<User> $usersFound
     * @todo improve this with elastic search
     */
    public function searchUsersFullnameForNetwork(User $user, Network $network, $search)
    {
        $users = $network->getUsers();
        $usersFound = array();
        foreach ($users as $user) {
            $found = true;
            if (!empty($search)) {
        old todo....old todo....old todo....old todo....$search);
                if ($pos !== false && $pos === 0) {
                    $usersFound[] = $user;
                }
            }
        }

        return $usersFound;
    }

    public function incrementUnreadNotifications(User $user)
    {
        $this->objectManager->incrementUnreadNotifications($user);
        $this->objectManager->persist($user);

        return $user;
    }

    public function decrementUnreadNotifications(User $user)
    {
        $this->objectManager->decrementUnreadNotifications($user);
        $this->objectManager->persist($user);

        return $user;
    }

    /**
     * Find users with $search included in $users.fullname
     *
     * @param User $user
     * @param Project $project
     * @param String $search
     * @param integer $limit
     * @return array<User> $usersFound
     */
    public function searchUserInRestrictedProject(User $user, Project $project, $search, $limit = null, User $excludeUser = null)
    {
        $users = $project->getRestrictedUsers();
        $usersFound = array();
        $i = 0;
        foreach ($users as $user) {
            if ($this->strSearchUtil->ngram($search, $user->getFullname()) && ($excludeUser === null || $user->getId() !== $excludeUser->getId())) {
                $usersFound[] = $user;
                if ($limit !== null && $i >= $limit-1) {
                    break;
                }
                $i++;
            }
        }

        return $usersFound;
    }

    /*
     * Send the account verification email to the $user email address
     * Save the token in redis with an expiration time
     *
     *
     * @param User $user
     * @param bool $checkVerifiedSilent : don't throw an exception if the account is already verified
     * @return void
     */
    public function sendVerificationEmail(User $user, $checkVerifiedSilent = false)
    {
        if ($user->isVerified()) {
            if (!$checkVerifiedSilent) {
                throw new IntegrityConstraintException($this->translator->trans("core.integrityconstraintexception.user_account_already_verified"));
            }
        } else {
            //generate the verification token
            $token = $this->objectManager->generateVerificationToken($user);

            //Save the key in redis with an expiration time
            $redisKey = $this->getVerificationTokenRedisKey($token);
            $this->redisClient->set($redisKey, $user->getId());
            $expiration = $this->verificationTokenLifetime;
            $this->redisClient->expire($redisKey, $expiration);

            //Send an email with the token
            $this->prepareAndSendVerificationEmail($user, $token);
        }
    }

    private function getVerificationTokenRedisKey($verificationToken)
    {
        $redisKey = sprintf("%s%s", self::VERIFICATION_TOKEN_REDIS_KEY_PREFIX, $verificationToken);

        return $redisKey;
    }

    /*
     * Prepare and send the email to the $user email address including the link to verify the $user account
     *
     * @param User $user
     * @param string $token
     * @return void
     */
    private function prepareAndSendVerificationEmail(User $user, $token)
    {
        $subjectParams = array(
                "%user_fullname%" => $user->getFullname()
        );
        $subject = $this->translator->trans("email.useraccount.user_verification_subject", $subjectParams);
        $emailAddress = $user->getEmail();

        $urlParams = array(
            "token" => $token,
            "email" => $emailAddress
        );
        $verificationUrl = $this->router->generate("producteev_web_user_verification", $urlParams, true);

        $templateParams = array(
            "user_fullname" => $user->getFullname(),
            "verification_url" => $verificationUrl
        );
        $categories = array(
            "userVerification"
        );
        $template = "user.verification";
        //send the email
        $this->emailManager->prepareAndSend($emailAddress, $subject, $template, $templateParams, $categories);
    }


    /**
    * Change the user password if the passwordToken is valid and if the newPassword respect rules and equals confirmation
    *
    * @param String $email
    * @param String $verificationToken
    * @return User $user
    */
    public function verifyUserAccount($email, $verificationToken)
    {
        //Get the user by email address
        $user = $this->objectManager->findOneByEmail($email);
        if ($user == null) {
            throw new InputInvalidException($this->translator->trans("core.inputinvalidexception.unknown_email_address", array("%email%" => $email)));
        }

        if ($user->isVerified()) {
            throw new IntegrityConstraintException($this->translator->trans("core.integrityconstraintexception.user_account_already_verified"));
        }

        // check if the password token is valid by checking in redis store
        $redisKey = $this->getVerificationTokenRedisKey($verificationToken);
        if ($this->redisClient->get($redisKey) !== $user->getId()) {
            throw new InputInvalidException($this->translator->trans("core.inputinvalidexception.user_verification_invalid_token"));
        }

        //switch the user account to verify and persist
        $this->switchToVerified($user);

        //Remove the key in redis
        $this->redisClient->del($redisKey);

        return $user;
    }

    /**
    * Turn a $user account to verified
    *
    * @param User $user
    * @return User $user
    */
    public function switchToVerified(User $user)
    {
        if (!$user->isVerified()) {
            $this->objectManager->switchToVerified($user);
            $this->objectManager->persist($user);

            //Send event user verified
            $event = new UserEvent($user);
            $this->eventDispatcher->dispatch(UserEvent::VERIFIED, $event);
        }

        return $user;
    }

    /**
    * Turn a $user account to unverified
    *
    * @param User $user
    * @return User $user
    */
    public function switchToUnverified(User $user)
    {
        if ($user->isVerified()) {
            $this->objectManager->switchToUnverified($user);
            $this->objectManager->persist($user);
        }

        return $user;
    }

    /**
    * Set the user date format
    * @param User $user
    * @param string $dateFormat
    * @return User $user
    */
    public function setDateFormat(User $user, $dateFormat)
    {
        $this->objectManager->setDateFormat($user, $dateFormat);
        $this->objectManager->persist($user);

        return $user;
    }

    public function searchByEmail(User $user, $search, $excludeLoggedInUser = true)
    {
        $networks = $this->networkService->findAllForUser($user);
        $results = $this->objectManager->searchByEmailInNetworks($user, $networks, $search, $excludeLoggedInUser);

        return $results;
    }

    public function setPasswordKnown(User $user)
    {
        $this->objectManager->setPasswordKnown($user);
        $this->objectManager->persist($user);

        return $user;
    }

    public function setPasswordUnknown(User $user)
    {
        $this->objectManager->setPasswordUnknown($user);
        $this->objectManager->persist($user);

        return $user;
    }
}