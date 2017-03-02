<?php


namespace ApiBundle\Entity;

use FOS\UserBundle\Entity\User as BaseUser;
use Doctrine\ORM\Mapping as ORM;

/**
 * User
 *
 * @ORM\Table("users")
 * @ORM\Entity
 */
class User extends BaseUser
{
    /**
     * @var integer
     *
     * @ORM\Column(name="id", type="integer")
     * @ORM\Id
     * @ORM\GeneratedValue(strategy="AUTO")
     */
    protected $id;

    /**
     * @var string
     *
     * @ORM\Column(name="firstname", type="string", nullable=true)
     */
    protected $firstname;

    /**
     * @var string
     *
     * @ORM\Column(name="lastname", type="string", nullable=true)
     */
    protected $lastname;

    /**
     * @var datetime
     *
     * @ORM\Column(name="dob", type="datetime", nullable=true)
     */
    protected $dob;

    /**
    * @var string $image
    * @ORM\Column(name="image", nullable=true)
    */
    protected $image;

    /**
     * Get id
     *
     * @return integer
     */
    public function getId()
    {
        return $this->id;
    }

    public function getFirstname()
    {
        return $this->firstname;
    }

    public function setFirstname($firstname)
    {
        $this->firstname = $firstname;

        return $this;
    }

    public function getLastname()
    {
      return $this->lastname;
    }

    public function setLastname($lastname)
    {
        $this->lastname = $lastname;

        return $this;
    }

    public function getDob()
    {
        return $this->dob;
    }

    public function setDob($dob)
    {
        // $dob is string from API and datetime object from web
        $this->dob = is_string($dob) ?  new \DateTime($dob) : $dob;

        return $this;
    }

    public function dobString()
    {
      if (!$this->dob) {
        return "Null Date of Birth";
      }

      $result = $this->dob->format('m-d-Y');

      if ($result) {
          return $result;
      } else { // format failed
          return "Malformed date of birth";
      }
    }

    /**
     * Set image
     *
     * @param string $image
     *
     * @return Thread
     */
    public function setImage($image = null)
    {
        $this->image = $image;

        return $this;
    }

    /**
     * Get image
     *
     * @return string
     */
    public function getImage()
    {
        if (strpos($this->image, '/images/profile/') !== false) {
          return explode('/images/profile/', $this->image)[1];
        }

        return $this->image;
    }
}
