import os
import random
import datetime
from django.db import models
from django.conf import settings
from django.utils.http import int_to_base36
from hashlib import sha1 as sha_constructor
from django.utils.translation import ugettext_lazy as _
from django.contrib.auth.models import User
from django.core.mail import send_mail, EmailMultiAlternatives
from django.template.loader import render_to_string
from django.contrib.sites.models import Site
from django.utils.timezone import now
from django.utils.html import strip_tags
from django.utils.safestring import mark_safe
from django.core.urlresolvers import reverse
from django.core.files.storage import default_storage

#token imports
from PIL import Image, ImageFont, ImageDraw, ImageOps
from picklefield.fields import PickledObjectField
import urllib2
from django.core.files.temp import NamedTemporaryFile
from django.core.files import File
from urlparse import urlparse, urlunparse
from django.db import connection


if getattr(settings, 'INVITATION_USE_ALLAUTH', False):
    import re
    SHA1_RE = re.compile('^[a-f0-9]{40}$')
else:    
    from registration.models import SHA1_RE

# prevent error on initial syncdb for apps that incorporate django-invitaion
#try:
#    site = Site.objects.get_current()
#    root_url = 'http://%s' % site.domain
#except:
#    connection.close()

def get_root_url():
    site = Site.objects.get_current()
    return 'http://%s' % site.domain
    
class InvitationKeyManager(models.Manager):
    def get_key(self, invitation_key):
        """
        Return InvitationKey, or None if it doesn't (or shouldn't) exist.
        """
        try:
            key = self.get(key=invitation_key)
        except self.model.DoesNotExist:
            return None
        
        return key
        
    def is_key_valid(self, invitation_key):
        """
        Check if an ``InvitationKey`` is valid or not, returning a valid key
        or false.
        """
        invitation_key = self.get_key(invitation_key)
        if invitation_key and invitation_key.is_usable():
            return invitation_key
        return False

    def create_invitation(self, user, recipient=('recipient@email.com', 'Sirname', 'Lastname' ), save=True):
        """
        Create an ``InvitationKey`` and returns it.
        
        The key for the ``InvitationKey`` will be a SHA1 hash, generated 
        from a combination of the ``User``'s username and a random salt.
        """
        salt = sha_constructor(str(random.random())).hexdigest()[:5]
        key = sha_constructor("%s%s%s" % (datetime.datetime.now(), salt, user.username)).hexdigest()
        if not save:
            return InvitationKey(from_user=user, key='previewkey00000000', recipient=recipient, date_invited=datetime.datetime.now())
        return self.create(from_user=user, key=key, recipient=recipient)
    
    def create_bulk_invitation(self, user, key, uses, recipient):
        """ Create a set of invitation keys - these can be used by anyone, not just a specific recipient """
        return self.create(from_user=user, key=key, uses_left=uses, recipient=None)

    def remaining_invitations_for_user(self, user):
        """
        Return the number of remaining invitations for a given ``User``.
        """
        invitation_user, created = InvitationUser.objects.get_or_create(
            inviter=user,
            defaults={'invitations_remaining': settings.INVITATIONS_PER_USER})
        return invitation_user.invitations_remaining

    def delete_expired_keys(self):
        for key in self.all():
            if key.key_expired():
                key.delete()


class InvitationKey(models.Model):
    key = models.CharField(_('invitation key'), max_length=40)
    date_invited = models.DateTimeField(_('date invited'), 
                                        auto_now_add=True)
    from_user = models.ForeignKey(User, 
                                  related_name='invitations_sent')
    registrant = models.ManyToManyField(User, null=True, blank=True, 
                                  related_name='invitations_used')
    uses_left = models.IntegerField(default=1)
    
    objects = InvitationKeyManager()
    
    recipient = PickledObjectField(default=None, null=True)
    
    def __unicode__(self):
        return u"Invitation from %s on %s (%s)" % (self.from_user.username, self.date_invited, self.key)
    
    def is_usable(self):
        """
        Return whether this key is still valid for registering a new user.        
        """
        return self.uses_left > 0 and not self.key_expired()
    
    def key_expired(self):
        """
        Determine whether this ``InvitationKey`` has expired, returning 
        a boolean -- ``True`` if the key has expired.
        
        The date the key has been created is incremented by the number of days 
        specified in the setting ``ACCOUNT_INVITATION_DAYS`` (which should be 
        the number of days after invite during which a user is allowed to
        create their account); if the result is less than or equal to the 
        current date, the key has expired and this method returns ``True``.
        
        """
        expiration_date = datetime.timedelta(days=settings.ACCOUNT_INVITATION_DAYS)
        return self.date_invited + expiration_date <= now()
    key_expired.boolean = True
    
    def mark_used(self, registrant):
        """
        Note that this key has been used to register a new user.
        """
        self.uses_left -= 1
        self.registrant.add(registrant)
        default_storage.delete('tokens/%s.png' % self.key)
        self.save()
    
    def get_context(self, sender_note=None):
        invitation_url = get_root_url() + reverse('invitation_invited', kwargs={'invitation_key':self.key})
        exp_date = self.date_invited + datetime.timedelta(days=settings.ACCOUNT_INVITATION_DAYS)
        context = { 'invitation_key': self,
                    'expiration_days': settings.ACCOUNT_INVITATION_DAYS,
                    'from_user': self.from_user,
                    'sender_note': sender_note,
                    'site': Site.objects.get_current().domain,
                    'root_url': get_root_url(),
                    'expiration_date': exp_date,
                    'recipient': self.recipient,
                    'token': self.generate_token(invitation_url),
                    'invitation_url':invitation_url}
        return context
    
    def send_to(self, from_email=settings.DEFAULT_FROM_EMAIL, sender_note=None,):
        """
        Send an invitation email to ``email``.
        """
        context = self.get_context(sender_note)
        
        subject = render_to_string('invitation/invitation_email_subject.txt', context)
        # Email subject *must not* contain newlines
        subject = ''.join(subject.splitlines())

        message_html = render_to_string('invitation/invitation_email.html',context)
        context.update({'sender_note':mark_safe(strip_tags(sender_note))})
        message = render_to_string('invitation/invitation_email.txt',context)
        msg = EmailMultiAlternatives(subject, message, from_email, [self.recipient[0]])
        msg.attach_alternative(message_html, "text/html")
        msg.send()
    
    def generate_token(self, invitation_url):
        token_html = '<a style="display: inline-block;" href="'+invitation_url+'">Click Me</a>'
        return token_html
        
class InvitationUser(models.Model):
    inviter = models.ForeignKey(User, unique=True)
    invitations_remaining = models.IntegerField()

    def __unicode__(self):
        return u"InvitationUser for %s" % self.inviter.username

    
def user_post_save(sender, instance, created, **kwargs):
    """Create InvitationUser for user when User is created."""
    if created:
        invitation_user = InvitationUser()
        invitation_user.inviter = instance
        invitation_user.invitations_remaining = settings.INVITATIONS_PER_USER
        # prevent error on syncdb when superuser is created
        try:
            invitation_user.save()
        except:
            connection.close()

models.signals.post_save.connect(user_post_save, sender=User)

def invitation_key_post_save(sender, instance, created, **kwargs):
    """Decrement invitations_remaining when InvitationKey is created."""
    if created:
        invitation_user = InvitationUser.objects.get(inviter=instance.from_user)
        remaining = invitation_user.invitations_remaining
        invitation_user.invitations_remaining = remaining-1
        invitation_user.save()

models.signals.post_save.connect(invitation_key_post_save, sender=InvitationKey)

def invitation_key_pre_delete(sender, instance, **kwargs):
    """Delete token image."""
    try:
        default_storage.delete('tokens/%s.png' % instance.key)
    except:
        pass

models.signals.post_delete.connect(invitation_key_pre_delete, sender=InvitationKey)
