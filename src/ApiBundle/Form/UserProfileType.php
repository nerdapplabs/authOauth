<?php

namespace ApiBundle\Form;

use ApiBundle\Entity\User;

use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\FileType;
use Symfony\Component\Form\Extension\Core\Type\EmailType;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\Extension\Core\Type\DateType;
use Symfony\Component\Form\Extension\Core\Type\CollectionType;
use Symfony\Component\Form\Extension\Core\Type\ChoiceType;

use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;

class UserProfileType extends AbstractType
{
    /**
     * @param FormBuilderInterface $builder
     * @param array $options
     */
    public function buildForm(FormBuilderInterface $builder, array $options)
    {
        $builder
            ->add('image', FileType::class, array('data_class' => null,'label' => 'Image, if any ', 'required' => false) )
            ->add('firstname',TextType::class)
            ->add('lastname',TextType::class, array('required' => false))
            ->add('dob', DateType::class, array('widget' => 'single_text', 'format' => 'M/d/y'))
            ->add('email', EmailType::class)
            ->add('username', TextType::class)
        ;
    }

    /**
     * @param OptionsResolver $resolver
     */
    public function configureOptions(OptionsResolver $resolver)
    {
        $resolver->setDefaults(array(
            'data_class' => 'ApiBundle\Entity\User',
            'csrf_protection' => true,
            'intention'  => 'profile',
            'validation_groups' => array('Profile')
        ));
    }

    public function getName()
    {
        return 'user_profile';
    }
}
