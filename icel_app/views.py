from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.tokens import default_token_generator
from django.core.files.storage import FileSystemStorage
from django.core.mail import send_mail
from django.shortcuts import redirect, render
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.views import View

from .forms import SignUpForm


# Homepage view
@login_required
def homepage(request):
    return render(request, "homepage.html")


def incident_form(request):
    if request.method == "POST":
        id_no = request.POST.get("id_no")
        date = request.POST.get("date")
        department = request.POST.get("department")
        location = request.POST.get("location")
        description = request.POST.get("description")
        corrective_action = request.POST.get("corrective_action")
        date_observed = request.POST.get("date_observed")
        date_reported = request.POST.get("date_reported")
        observed_by = request.POST.get("observed_by")
        category = request.POST.get("category")
        incident_types = request.POST.getlist(
            "incident_type"
        )  # Updated from "incident_types" to "incident_type" to match the name in your HTML.
        upload = request.FILES.get("incident_upload")

        # Save the uploaded file
        uploaded_file_url = None
        if upload:
            fs = FileSystemStorage()
            filename = fs.save(upload.name, upload)
            uploaded_file_url = fs.url(filename)

        # Construct the email
        subject = f"Incident Report from {observed_by}"
        message = f"""
        ID No.: {id_no}
        Date: {date}
        Department: {department}
        Location: {location}
        Incident Description: {description}
        Corrective Action: {corrective_action}
        Date Observed: {date_observed}
        Date Reported: {date_reported}
        Category: {category}
        Incident Types: {', '.join(incident_types)}
        Uploaded File: {uploaded_file_url if upload else 'No file uploaded'}
        """

        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            ["isaiahdurojaiye9@gmail.com"],
            fail_silently=False,
        )

        return redirect("homepage")
    return render(request, "incident_form.html")


# POOL_CAR_request_view
def pool_car_request(request):
    if request.method == "POST":
        date_requested = request.POST.get("R-datecheckin")
        requestor_name = request.POST.get("requestor_name")
        phone_number = request.POST.get("phone_number")
        car_no = request.POST.get("car_no")
        pick_up_location = request.POST.get("pick_up_location")
        drop_off_destination = request.POST.get("drop_off_destination")
        return_location = request.POST.get("return_location")
        purpose_of_trip = request.POST.get("purpose_of_trip")
        departure_date = request.POST.get("departure_date")
        return_date = request.POST.get("return_date")
        departure_time = request.POST.get("departure_time")
        estimated_return_time = request.POST.get("estimated_return_time")
        director_name = request.POST.get("director_name")
        director_designation = request.POST.get("director_designation")
        director_email = request.POST.get("director_email")

        subject = f"Pool Car Request from {requestor_name}"
        message = f"""
        Date Requested: {date_requested}
        Requestor Name: {requestor_name}
        Phone Number: {phone_number}
        Number of Cars: {car_no}
        Pick-up Location: {pick_up_location}
        Drop-off Destination: {drop_off_destination}
        Return Location: {return_location}
        Purpose of Trip: {purpose_of_trip}
        Departure Date: {departure_date}
        Return Date: {return_date}
        Departure Time: {departure_time}
        Estimated Return Time: {estimated_return_time}
        Director/Supervisor Name: {director_name}
        Director/Supervisor Designation: {director_designation}
        Director/Supervisor Email: {director_email}
        """
        try:
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                ["isaiahdurojaiye9@gmail.com", "ayokanmiamos@gmail.com"],
                fail_silently=False,
            )
            return redirect("homepage")
        except Exception as e:
            print(f"Error sending email: {e}")
            return render(
                request, "pool_car_request.html", {"error": "Failed to send the email."}
            )

    return render(request, "pool_car_request.html")


def travel_notice(request):
    if request.method == "POST":
        # Handle Travel By Air form submission
        if "trip-type" in request.POST:  # Check if it's the air travel form
            passenger_names = request.POST.getlist("passenger_name")
            trip_type = request.POST.get("trip-type")
            preferred_airline = request.POST.get("preferred_airline")
            preferred_flight_class = request.POST.get("preferred_flight_class")
            ticket_type = request.POST.get("ticket-type")
            flight_type = request.POST.get("flight-type")
            routes = request.POST.get("routes")
            departure_date = request.POST.get("checkin")
            preferred_departure_time = request.POST.get("departure-time")
            arrival_date = request.POST.get("arrival_date")
            preferred_arrival_time = request.POST.get("arrival-time")
            luggage_weight = request.POST.get("luggage_weight")

            # Prepare email content for air travel
            email_subject = "New Travel By Air Form Submission"
            email_body = f"""
            Passenger Names: {', '.join(passenger_names)}
            Trip Type: {trip_type}
            Preferred Airline: {preferred_airline}
            Preferred Flight Class: {preferred_flight_class}
            Ticket Type: {ticket_type}
            Flight Type: {flight_type}
            Routes: {routes}
            Departure Date: {departure_date}
            Preferred Departure Time: {preferred_departure_time}
            Arrival Date: {arrival_date}
            Preferred Arrival Time: {preferred_arrival_time}
            Luggage Weight: {luggage_weight}
            """

            # Send email for air travel
            send_mail(
                email_subject,
                email_body,
                "from@example.com",  # Replace with your email
                ["recipient@example.com"],  # Replace with the recipient's email
                fail_silently=False,
            )

        # Handle Travel By Road form submission
        elif "vehicle-type" in request.POST:  # Check if it's the car travel form
            car_passenger_names = request.POST.getlist("passenger_name")
            vehicle_type = request.POST.get("vehicle-type")
            journey_type = request.POST.get("journey-type")
            departure_location = request.POST.get("departure-location")
            departure_date_car = request.POST.get("checkin")
            preferred_departure_time_car = request.POST.get("departure-time")
            destination_location = request.POST.get("destination")
            return_location = request.POST.get("return-location")
            expected_arrival_date = request.POST.get("arrival-date")
            expected_arrival_time = request.POST.get("arrival-time")
            security_escort = request.POST.get("secrity-escort")

            # Prepare email content for car travel
            email_subject_car = "New Travel By Road Form Submission"
            email_body_car = f"""
            Car Passenger Names: {', '.join(car_passenger_names)}
            Vehicle Type: {vehicle_type}
            Journey Type: {journey_type}
            Departure Location: {departure_location}
            Departure Date: {departure_date_car}
            Preferred Departure Time: {preferred_departure_time_car}
            Destination Location: {destination_location}
            Return Location: {return_location}
            Expected Arrival Date: {expected_arrival_date}
            Expected Arrival Time: {expected_arrival_time}
            Security Escort: {security_escort}
            """

            # Send email for car travel
            send_mail(
                email_subject_car,
                email_body_car,
                "from@example.com",  # Replace with your email
                ["recipient@example.com"],  # Replace with the recipient's email
                fail_silently=False,
            )

        return redirect("success")  # Redirect to a success page or similar

    return render(request, "travel.html")  # Render the form on GET request


def contact_view(request):
    if request.method == "POST":
        first_name = request.POST.get("firstName")
        last_name = request.POST.get("lastName")
        email = request.POST.get("email")
        phone = request.POST.get("phone")
        message = request.POST.get("message")

        # Compose the email
        subject = "Contact Form Submission"
        message_body = f"Name: {first_name} {last_name}\nEmail: {email}\nPhone: {phone}\nMessage: {message}"
        recipient_list = ["itsupport@imperialcrestenergy.com"]

        # Send email
        send_mail(subject, message_body, settings.DEFAULT_FROM_EMAIL, recipient_list)

        return redirect("success_url")  # Redirect to a success page or the same page

    return render(request, "contact.html")


# Requisitions view
def requisitions(request):
    return render(request, "requisitions.html")


def logout_view(request):
    print("logging out")
    logout(request)
    return redirect(settings.LOGOUT_REDIRECT_URL)


def signup_view(request):
    if request.method == "POST":
        form = SignUpForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.set_password(form.cleaned_data["password"])
            user.save()
            messages.success(request, "Account created successfully.")
            return redirect("index")  # Redirect to login page after signup
    else:
        form = SignUpForm()
    return render(request, "signup.html", {"form": form})


def login_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        # Authenticate user
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            redirect_url = (
                request.POST.get("next") or request.GET.get("next") or "homepage"
            )
            return redirect(redirect_url)
        else:
            messages.error(request, "Invalid username or password.")

    return render(request, "index.html")


class ForgotPasswordView(View):
    def get(self, request):
        return render(request, "forgot_password.html")

    def post(self, request):
        email = request.POST["email"]
        try:
            user = User.objects.get(email=email)
            subject = "Password Reset Requested"
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            link = f"{request.build_absolute_uri('/reset-password/')}{uid}/{token}/"
            send_mail(
                subject,
                f"Click the link to reset your password: {link}",
                settings.DEFAULT_FROM_EMAIL,
                [email],
            )
            return render(
                request,
                "forgot_password.html",
                {"message": "Check your email for a reset link."},
            )
        except User.DoesNotExist:
            return render(
                request,
                "forgot_password.html",
                {"error": "No account found with this email."},
            )
