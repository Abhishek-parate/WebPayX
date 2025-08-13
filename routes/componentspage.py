from flask import render_template
from flask import Blueprint

componentspage_bp = Blueprint('componentspage', __name__, template_folder='templates', static_folder='static')

@componentspage_bp.route('/mobile-recharge')
def alert():
    return render_template('componentspage/alert.html',
        title='Mobile Recharge',
        subtitle='Self Services / Mobile Recharge'
    )

@componentspage_bp.route('/avatar')
def avatar():
    return render_template('componentspage/avatar.html',
        title='Avatars',
        subtitle='Components / Avatars'
    )

@componentspage_bp.route('/badges')
def badges():
    return render_template('componentspage/badges.html',
        title='Badges',
        subtitle='Components / Badges'
    )

@componentspage_bp.route('/cc-bill-payment-service')
def button():
    return render_template('componentspage/button.html',
        title='CC Bill Payment Service',
        subtitle='Self Services / CC Bill Payment Service'
    )

@componentspage_bp.route('/calendar')
def calendar():
    return render_template('componentspage/calendar.html',
        title='Calendar',
        subtitle='Components / Calendar',
        multi_script=['assets/js/flatpickr.js', 'assets/js/full-calendar.js']
    )

@componentspage_bp.route('/dth-recharge')
def card():
    return render_template('componentspage/card.html',
        title='DTH Recharge',
        subtitle='Self Services / DTH Recharge'
    )

@componentspage_bp.route('/carousel')
def carousel():
    return render_template('componentspage/carousel.html',
        title='Carousel',
        subtitle='Components / Carousel',
        script='assets/js/defaultCarousel.js'
    )

@componentspage_bp.route('/payment-gateway-services')
def colors():
    return render_template('componentspage/colors.html',
        title='Payment Gateway Services',
        subtitle='Self Services / Payment Gateway Services'
    )

@componentspage_bp.route('/money-transfer-service')
def dropdown():
    return render_template('componentspage/dropdown.html',
        title='Money Transfer Service',
        subtitle='Self Services / Money Transfer Service'
    )

@componentspage_bp.route('/image-upload')
def imageUpload():
    return render_template('componentspage/imageUpload.html',
        title='Radio',
        subtitle='Components / Radio'
    )

@componentspage_bp.route('/lists')
def lists():
    return render_template('componentspage/lists.html',
        title='List',
        subtitle='Components / List'
    )

@componentspage_bp.route('/pagination')
def pagination():
    return render_template('componentspage/pagination.html',
        title= 'Pagination',
        subtitle='Components / Pagination'
    )

@componentspage_bp.route('/progress')
def progress():
    return render_template('componentspage/progress.html',
        title= 'Progress Bar',
        subtitle='Components / Progress Bar'
    )

@componentspage_bp.route('/radio')
def radio():
    return render_template('componentspage/radio.html',
        title= 'Radio',
        subtitle='Components / Radio'
    )

@componentspage_bp.route('/star-rating')
def starRating():
    return render_template('componentspage/starRating.html',
        title= 'Star Ratings',
        subtitle='Components / Star Ratings'
    )

@componentspage_bp.route('/switch')
def switch():
    return render_template('componentspage/switch.html',
        title= 'Radio',
        subtitle='Components / Radio'
    )

@componentspage_bp.route('/tabs')
def tabs():
    return render_template('componentspage/tabs.html',
        title= 'Tab & Accordion',
        subtitle='Components / Tab & Accordion'
    )

@componentspage_bp.route('/tags')
def tags():
    return render_template('componentspage/tags.html',
        title= 'Tags',
        subtitle='Components / Tags'
    )

@componentspage_bp.route('/tooltip')
def tooltip():
    return render_template('componentspage/tooltip.html',
        title= 'Tooltip & Popover',
        subtitle='Components / Tooltip & Popover',
        script='assets/js/defaultCarousel.js'
    )

@componentspage_bp.route('/member-wallet-top-up-report')
def typography():
    return render_template('componentspage/typography.html',
        title= 'Wallet Top-up Report',
        subtitle='Member Report / Wallet Top-up Report'
    )

@componentspage_bp.route('/videos')
def videos():
    return render_template('componentspage/videos.html',
        title= 'Videos',
        subtitle='Components / Videos'
    )