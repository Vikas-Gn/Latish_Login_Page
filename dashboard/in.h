<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HRM Dashboard</title>
    <link href='https://unpkg.com/boxicons@2.0.9/css/boxicons.min.css' rel='stylesheet'>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.2.1/css/all.min.css" />
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/flag-icons/6.6.6/css/flag-icons.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap-icons/1.8.1/font/bootstrap-icons.min.css">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Lato:wght@400;700&family=Poppins:wght@400;500;600;700&display=swap');

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        a {
            text-decoration: none;
        }

        li {
            list-style: none;
        }

        :root {
            --poppins: 'Poppins', sans-serif;
            --lato: 'Lato', sans-serif;
            --light: #F9F9F9;
            --blue: #3C91E6;
            --light-blue: #CFE8FF;
            --grey: #eee;
            --dark-grey: #AAAAAA;
            --dark: #342E37;
            --red: #DB504A;
            --yellow: #FFCE26;
            --light-yellow: #FFF2C6;
            --orange: #FD7238;
            --light-orange: #FFE0D3;
        }

        html {
            overflow-x: hidden;
            scrollbar-width: thin;
            /* scrollbar-color: transparent transparent; */
        }

        body.dark {
            --light: #0C0C1E;
            --grey: #060714;
            --dark: #FBFBFB;
        }

        body {
            background: var(--grey);
            overflow: hidden;
            height: 1000px;
        }

        .language-selector {
            cursor: pointer;
            display: flex;
            align-items: center;
            font-size: 16px;
            margin-left: -20px;
        }

        .country-dropdown {
            display: none;
            position: absolute;
            top: 110px;
            left: 0;
            border: 1px solid #000000;
            background-color: white;
            width: 220px;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
            padding: 10px;
            margin-left: 75%;
        }

        .language-list {
            list-style: none;
            padding: 0;
            margin: 0;
        }

        .language-list li {
            padding: 8px 10px;
            cursor: pointer;
        }

        .language-list li:hover {
            background-color: #f0f0f0;
        }

        .profile-section {
            display: flex;
            align-items: center;
            cursor: pointer;
            position: relative;
            box-shadow: 0 3px 6px rgba(0, 0, 0, 0.1);
            width: 150px;
            border-radius: 20px;
            margin: auto;
            border-color: #dadada;
            margin-left: 0px;
        }

        .profile-img {
            width: 70px;
            height: 70px;
            border-radius: 50%;
            object-fit: cover;
            border: 2px solid #4f8ff7;
            margin-right: 10px;
            transition: border 0.3s ease;
            position: relative;
            margin-top: 5px;
        }

        .online-dot {
            position: absolute;
            bottom: 5px;
            right: 60%;
            width: 13px;
            height: 13px;
            background-color: #4CAF50;
            border-radius: 50%;
            border: 2px solid white;
        }

        .profile-img:hover {
            border-color: #1dbf73;
        }

        .profile-dropdown {
            display: flex;
            align-items: center;
            color: #333;
            font-weight: bold;
            font-size: 14px;
        }

        .profile-dropdown i {
            margin-left: 5px;
            font-size: 12px;
            color: #333;
            transition: transform 0.3s ease;
        }

        .profile-dropdown i:hover {
            transform: rotate(180deg);
        }

        .profile-menu {
            display: none;
            position: absolute;
            background-color: white;
            border: 1px solid #ccc;
            border-radius: 4px;
            top: 40px;
            right: 50px;
            width: 150px;
            z-index: 10;
            box-shadow: 0 3px 6px rgba(0, 0, 0, 0.1);
            padding: 10px 0;
            margin-top: 20px;
        }

        .profile-menu ul {
            list-style-type: none;
            margin: 0;
            padding: 0;
        }

        .profile-menu ul li {
            padding: 8px 15px;
            transition: background-color 0.3s ease;
        }

        .profile-menu ul li:hover {
            background-color: #f1f1f1;
        }

        .profile-menu ul li a {
            color: #333;
            text-decoration: none;
            font-size: 14px;
            display: block;
        }

        .profile-menu ul li a:hover {
            color: #1dbf73;
        }

        .profile-section.active .profile-menu {
            display: block;
        }

        .icons {
            display: flex;
            align-items: center;
            justify-content: flex-start;
            gap: 25px;
            padding: 20px;
            border-radius: 8px;
            margin: 20px;
            transition: all 0.3s ease-in-out;
        }

        .icons img {
            transition: transform 0.3s ease, filter 0.3s ease;
            cursor: pointer;
            border-radius: 8px;
        }

        .icons img:hover {
            transform: scale(1.1);
            filter: brightness(1.2);
        }

        .fullscreen-icon {
            cursor: pointer;
            border-radius: 50%;
            background-color: #f4f4f4;
            padding: 5px;
            transition: background-color 0.3s ease, transform 0.3s ease;
            margin-left: 20px;
        }

        .fullscreen-icon:hover {
            background-color: #007bff;
            transform: scale(1.1);
        }

        #search-wrapper {
            display: flex;
            border: 1px solid rgba(0, 0, 0, 0.276);
            align-items: stretch;
            border-radius: 50px;
            background-color: #fff;
            overflow: hidden;
            max-width: 400px;
            height: 40px;
            box-shadow: 2px 1px 5px 1px rgba(0, 0, 0, 0.273);
        }

        #search {
            border: none;
            width: 350px;
            font-size: 15px;
        }

        #search:focus {
            outline: none;
        }

        .search-icon {
            margin: 10px;
            color: rgba(0, 0, 0, 0.564);
        }

        #search-button {
            border: none;
            cursor: pointer;
            color: #fff;
            background-color: #3C91E6;
            padding: 0px 10px;
        }

        .mic-icon {
            margin-top: 10px;
            margin-right: 10px;
            margin-left: 10px;
            color: #777;
            cursor: pointer;
        }

        #sidebar {
            top: 0;
            left: 0;
            width: 250px;
            height: 100%;
            background: var(--light);
            z-index: 2000;
            font-family: var(--lato);
            transition: .3s ease;
            overflow-x: hidden;
            scrollbar-width: none;
        }

        #sidebar::-webkit-scrollbar {
            display: none;
        }

        #sidebar.hide {
            width: 60px;
        }

        #sidebar .brand {
            font-size: 24px;
            font-weight: 700;
            height: 56px;
            display: flex;
            align-items: center;
            color: var(--blue);
            position: sticky;
            top: 0;
            left: 0;
            background: var(--light);
            z-index: 500;
            padding-bottom: 20px;
            box-sizing: content-box;
        }

        #sidebar .brand .bx {
            min-width: 60px;
            display: flex;
            justify-content: center;
        }

        #sidebar .side-menu {
            width: 100%;
            margin-top: 48px;
        }

        #sidebar .side-menu li {
            position: relative;
            transition: all 0.3s ease;
            background: transparent;
            margin-left: 6px;
            border-radius: 48px 0 0 48px;
            padding: 4px;
        }

        #sidebar .side-menu li.active {
            background: var(--grey);
            position: relative;
        }

        #sidebar .side-menu li.active::before {
            content: '';
            position: absolute;
            width: 40px;
            height: 40px;
            border-radius: 50%;
            top: -40px;
            right: 0;
            box-shadow: 20px 20px 0 var(--grey);
            z-index: -1;
        }

        #sidebar .side-menu li.active::after {
            content: '';
            position: absolute;
            width: 40px;
            height: 40px;
            border-radius: 50%;
            bottom: -40px;
            right: 0;
            box-shadow: 20px -20px 0 var(--grey);
            z-index: -1;
        }

        #sidebar .side-menu li a {
            width: 100%;
            height: 100%;
            background: var(--light);
            display: flex;
            align-items: center;
            border-radius: 48px;
            font-size: 16px;
            color: var(--dark);
            white-space: nowrap;
            overflow-x: hidden;
        }

        #sidebar .side-menu.top li.active a {
            color: var(--blue);
        }

        #sidebar.hide .side-menu li a {
            width: calc(48px - (4px * 2));
            transition: width .3s ease;
        }

        #sidebar .side-menu li a.logout {
            color: var(--red);
        }

        #sidebar .side-menu.top li a:hover {
            color: var(--blue);
        }

        #sidebar .side-menu li a .bx {
            min-width: calc(60px - ((4px + 6px) * 2));
            display: flex;
            justify-content: center;
        }

        #content {
            position: relative;
            width: 5px;
            left: 10px;
            margin-top: 50px;
            transition: .3s ease;
            z-index: 1000;
            display: flex;
        }

        #sidebar.hide~#content {
            width: calc(100% - 60px);
            left: 60px;
        }

        #content nav {
            cursor: pointer;
            height: 25px;
            width: 70px;
            border-radius: 5px;
            display: flex;
            align-items: center;
            grid-gap: 24px;
            font-family: var(--lato);
            position: sticky;
            top: 0;
            left: 0;
            z-index: 1000;
        }

        #content nav .bi.bi-chevron-compact-right:hover {
            color: var(--blue);
            transform: rotate(180deg);
        }

        #content nav::before {
            content: '';
            position: absolute;
            width: 0px;
            height: 40px;
            bottom: -40px;
            left: 0;
            box-shadow: -20px -20px 0 var(--light);
        }

        #content nav a {
            color: var(--dark);
        }

        #content nav .bx.bx-menu {
            cursor: pointer;
            color: var(--dark);
        }

        #content nav .nav-link {
            font-size: 16px;
            transition: .3s ease;
        }

        #content nav .nav-link:hover {
            color: var(--blue);
        }

        #content nav form {
            max-width: 400px;
            width: 100%;
            margin-right: auto;
        }

        #content nav form .form-input {
            display: flex;
            align-items: center;
            height: 36px;
        }

        #content nav form .form-input input {
            flex-grow: 1;
            padding: 0 16px;
            height: 100%;
            border: none;
            background: var(--grey);
            border-radius: 36px 0 0 36px;
            outline: none;
            width: 100%;
            color: var(--dark);
        }

        #content nav form .form-input button {
            width: 36px;
            height: 100%;
            display: flex;
            justify-content: center;
            align-items: center;
            background: var(--blue);
            color: var(--light);
            font-size: 18px;
            border: none;
            outline: none;
            border-radius: 0 36px 36px 0;
            cursor: pointer;
        }

        #content nav .notification {
            font-size: 20px;
            position: relative;
        }

        #content nav .notification .num {
            position: absolute;
            top: -6px;
            right: -6px;
            width: 20px;
            height: 20px;
            border-radius: 50%;
            border: 2px solid var(--light);
            background: var(--red);
            color: var(--light);
            font-weight: 700;
            font-size: 12px;
            display: flex;
            justify-content: center;
            align-items: center;
        }

        .submenu {
            display: none;
            list-style: none;
            padding: 0;
            margin: 0;
            background-color: #eee;
        }

        .submenu li a {
            padding-left: 40px;
            padding: 10px;
            font-size: 14px;
            color: var(--dark);
            transition: background-color 0.3s ease;
        }

        .submenu li a:hover {
            background-color: var(--blue);
            color: var(--light);
        }

        .submenu-toggle.rotate {
            transform: rotate(180deg);
        }

        #sidebar .side-menu li i {
            margin-right: 10px;
        }

        .submenu-toggle {
            margin-left: auto;
            font-size: 1.2em;
        }

        .animated-header {
            position: relative;
            top: -100px;
            animation: moveToOriginal 1s ease-out forwards;
            background: var(--light);
            color: black;
        }

        @keyframes moveToOriginal {
            from {
                top: -100px;
            }
            to {
                top: 0;
            }
        }

        /* Notification Modal Styles */
        .notification-modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.5);
            z-index: 3000;
            animation: fadeIn 0.3s ease-in-out;
        }

        .notification-container {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%) scale(0.7);
            background: white;
            border-radius: 20px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
            padding: 30px;
            width: 400px;
            text-align: center;
            animation: scaleIn 0.4s ease-out forwards;
            overflow: hidden;
        }

        .notification-icon {
            font-size: 55px;
            color: #3C91E6;
            margin-bottom: 20px;
            display: inline-block;
            animation: pulse 1.5s infinite;
        }

        .notification-title {
            font-size: 24px;
            font-weight: 600;
            color: #342E37;
            margin-bottom: 10px;
        }

        .notification-message {
            font-size: 16px;
            color: #666;
            margin-bottom: 25px;
        }

        .notification-buttons {
            display: flex;
            justify-content: center;
            gap: 15px;
        }

        .btn-notification {
            padding: 12px 25px;
            border-radius: 50px;
            font-size: 16px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s ease;
            border: none;
            outline: none;
        }

        .btn-confirm {
            background: linear-gradient(to right, #3C91E6, #1a74c7);
            color: white;
        }

        .btn-confirm:hover {
            background: linear-gradient(to right, #1a74c7, #0a5ca9);
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(60, 145, 230, 0.3);
        }

        .btn-cancel {
            background: #f2f2f2;
            color: #666;
        }

        .btn-cancel:hover {
            background: #e5e5e5;
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
        }

        /* Animations */
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        @keyframes scaleIn {
            from { transform: translate(-50%, -50%) scale(0.7); opacity: 0; }
            to { transform: translate(-50%, -50%) scale(1); opacity: 1; }
        }

        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.1); }
            100% { transform: scale(1); }
        }

        @keyframes slideIn {
            0% { transform: translateY(-100px); opacity: 0; }
            100% { transform: translateY(0); opacity: 1; }
        }

        /* Individual element animations */
        .animate-slide {
            opacity: 0;
            animation: slideIn 0.5s ease-out forwards;
        }

        .delay-100 { animation-delay: 0.1s; }
        .delay-200 { animation-delay: 0.2s; }
        .delay-300 { animation-delay: 0.3s; }
        .delay-400 { animation-delay: 0.4s; }
    </style>
</head>
<body>
    <section class="animated-header">
        <nav style="display: flex;">
            <img src="ATS Wallpaper.jpg" style="height: 100px; margin-left: 0px;border-radius: 20%; margin-top: 10px;" alt="">
            <section id="content">
                <nav>
                    <i class="bi bi-list fs-1 bi bi-chevron-compact-right" style="font-size: 28px;"></i>
                </nav>
            </section>
            <div class="icons">
                <div style="font-weight: 200; font-size: x-large;">Hello, <span id="username"></span>👋</div>
                <div id="search-wrapper">
                    <i class="search-icon fas fa-search"></i>
                    <input type="text" id="search" placeholder="Search here...">
                    <i class="mic-icon fas fa-microphone"></i>
                    <button id="search-button">Search</button>
                </div>
                <img width="45" height="45" src="https://img.icons8.com/external-linear-outline-icons-papa-vector/78/external-Exit-Full-Screen-interface-linear-outline-icons-papa-vector-2.png" alt="fullscreen-icon" class="fullscreen-icon" onclick="toggleFullscreen()"/>
                <img width="25" height="25" src="https://img.icons8.com/ios/50/secured-letter--v1.png" alt="secured-letter--v1"/>
                <img width="25" height="25" src="https://img.icons8.com/ios/50/appointment-reminders--v1.png" alt="appointment-reminders--v1"/>
                <img width="25" height="25" src="https://img.icons8.com/ios/50/geography--v2.png" alt="geography--v2" onclick="toggleCountryDropdown()"/> 
                <span class="language-selector" onclick="toggleCountryDropdown()">English</span>
                <div class="country-dropdown" id="countryDropdown">
                    <ul class="language-list">
                        <li><span class="fi fi-in"></span> Hindi (India)</li><hr>
                        <li><span class="fi fi-fr"></span> Français (France, Canada)</li><hr>
                        <li><span class="fi fi-sa"></span> Arabic (Saudi Arabia, Middle East)</li><hr>
                        <li><span class="fi fi-id"></span> Indonesian (Indonesia)</li><hr>
                        <li><span class="fi fi-gb"></span> English (UK, US)</li><hr>
                        <li><span class="fi fi-it"></span> Italian (Italy)</li><hr>
                        <li><span class="fi fi-ru"></span> Russian (Russia)</li>
                    </ul>
                </div>
            </div>
            <div class="profile-section">
                <a href="../HRM SERVICES/Employee_Profile/Employee_profile.html" target="contentFrame">
                    <img src="../Assests/ATS Wallpaper.jpg" alt="Profile" class="profile-img">
                </a>
                <div class="online-dot"></div>
                <span style="color: #4f8ff7;">Active</span>
                <div class="profile-dropdown">
                    <i class="bi bi-chevron-down" style="margin-left: 10px; color: #4f8ff7;"></i>
                </div>
            </div>
        </nav> 
    </section>
    <div style="display: flex; height: 100%;">
        <section id="sidebar">
            <ul class="side-menu top">
                <li class="active" onclick="toggleSubmenu('dashboard-submenu')">
                    <a href="javascript:void(0)" style="height: 48px;">
                        <i class='bx bxs-dashboard'></i>
                        <span class="text">Dashboard</span>
                        <i class='bx bx-chevron-down submenu-toggle'></i>
                    </a>
                    <ul id="dashboard-submenu" class="submenu">
                        <li><a href="#">HRM Dashboard</a></li>
                        <li><a href="#">Employee Dashboard</a></li>
                        <li><a href="#">CRM Analytics</a></li>
                    </ul>
                </li>
                <li onclick="toggleSubmenu('employee-services-submenu')">
                    <a href="javascript:void(0)" style="height: 48px;">
                        <i class='bx bx-group'></i>
                        <span class="text">HRM</span>
                        <i class='bx bx-chevron-down submenu-toggle'></i>
                    </a>
                    <ul id="employee-services-submenu" class="submenu">
                        <li onclick="toggleSubmenu('employee-services-1')">
                            <a href="javascript:void(0)" style="height: 48px;">
                                <span class="text">Employee_Services</span>
                                <i class='bx bx-chevron-down submenu-toggle'></i>
                            </a>
                            <ul id="employee-services-1" class="submenu">
                                <li><a href="../HRMS_HTML_pages/Attendance/Punch-In.html" target="contentFrame">Attendance Management</a></li>
                                <li><a href="../HRMS_HTML_pages/Payroll-software/Payroll.html" target="contentFrame">Payroll Software</a></li>
                                <li><a href="../HRMS_HTML_pages/Leave-Management/Leave.html" target="contentFrame">Leave Software</a></li>
                                <li><a href="../HRMS_HTML_pages/Claims-Software/Claim-front.html" target="contentFrame">Claims Software</a></li>
                                <li><a href="../HRMS_HTML_pages/Appraisal-software/Appraisal.html" target="contentFrame">Appraisal Software</a></li>
                                <li><a href="../HRMS_HTML_pages/Payroll&Payslip/payslip.html" target="contentFrame">Payroll Processing/Payslip</a></li>
                                <li><a href="../HRMS_HTML_pages/My-Assests/My Assests.html" target="contentFrame">My Assets</a></li>
                                <li><a href="../HRMS_HTML_pages/Carrer-Progression/Carrer-prog.html" target="contentFrame">Career Progression</a></li>
                                <li><a href="../HRMS_HTML_pages/Increament/Increament.html" target="contentFrame">Increment & Bonus</a></li>
                                <li><a href="../HRMS_HTML_pages/Notifications to staff/Notification.html" target="contentFrame">Notifications to Staffs</a></li>
                                <li><a href="../HRMS_HTML_pages/Training-Management/Training.html" target="contentFrame">Training Management</a></li>
                                <li><a href="../HRMS_HTML_pages/Offer_Letter/Form-filling.html" target="contentFrame">Job Application Form</a></li>
                            </ul>
                        </li>
                        <li onclick="toggleSubmenu('HRM-2')">
                            <a href="javascript:void(0)" style="height: 48px;">
                                <span class="text">HRM_Services</span>
                                <i class='bx bx-chevron-down submenu-toggle'></i>
                            </a>
                            <ul id="HRM-2" class="submenu">
                                <li><a href="#">Employee</a></li>
                                <li><a href="../HRM SERVICES/Employee_Profile/Employee_profile.html" target="contentFrame">Employee Profile</a></li>
                                <li><a href="../HRM SERVICES/Designation/Designation.html" target="contentFrame">Designations</a></li>
                                <li><a href="../HRM SERVICES/Admin_Attendance/Admin.html" target="contentFrame">Admin Attendance</a></li>
                                <li><a href="../HRM SERVICES/Employee_Attendance/EmpAtten.html" target="contentFrame">Employee Attendance</a></li>
                                <li><a href="#">Bio Metric Attendance</a></li>
                                <li><a href="../HRM SERVICES/Office_Loan/OfficeLoan.html" target="contentFrame">Office Loan</a></li>
                                <li><a href="#">Personal Loan</a></li>
                                <li><a href="#">Employee Leaves</a></li>
                                <li><a href="#">Admin Leaves</a></li>
                                <li><a href="../HRM SERVICES/Holidays/Holiday.html" target="contentFrame">Holidays</a></li>
                                <li><a href="../HRM SERVICES/Timesheet/Timesheet.html" target="contentFrame">Time Sheet</a></li>
                            </ul>
                        </li>
                        <li onclick="toggleSubmenu('HRM-3')">
                            <a href="javascript:void(0)" style="height: 48px;">
                                <span class="text">HR_Services</span>
                                <i class='bx bx-chevron-down submenu-toggle'></i>
                            </a>
                            <ul id="HRM-3" class="submenu">
                                <li><a href="../HR_SERVICES/On-boarding/On-boarding.html" target="contentFrame">On-Boarding</a></li>
                                <li><a href="../HR_SERVICES/Off-Boarding/Offboarding.html" target="contentFrame">Off-Boarding</a></li>
                                <li><a href="../HR_SERVICES/Attendance/attend.html" target="contentFrame">Attendance</a></li>
                                <li><a href="../HR_SERVICES/Leave-Management/Leave.html" target="contentFrame">Leave Software</a></li>
                                <li><a href="../HR_SERVICES/Claims-software/Claims.html" target="contentFrame">Claims Software</a></li>
                                <li><a href="../HR_SERVICES/Appraisal-software/Appraisal.html" target="contentFrame">Appraisal Software</a></li>
                                <li><a href="../HR_SERVICES/Payroll&Payslip/payslip.html" target="contentFrame">Payroll Processing/Payslip</a></li>
                                <li><a href="../HR_SERVICES/ESI&PF/ESI.html" target="contentFrame">ESI/Provident Fund</a></li>
                                <li><a href="../HR_SERVICES/Assests-Management/AssestsManag.html" target="contentFrame">Assets Management</a></li>
                                <li><a href="../HR_SERVICES/Increament/Increament.html" target="contentFrame">Increment & Bonus</a></li>
                                <li><a href="../HR_SERVICES/Notifications to staff/Notification.html" target="contentFrame">Notifications to Staffs</a></li>
                                <li><a href="../HR_SERVICES/Training-Management/Training.html" target="contentFrame">Training Management</a></li>
                                <li><a href="../HR_SERVICES/Offer_Letter/HR-Form-Filling.html" target="contentFrame">Offer_Letter</a></li>
                            </ul>
                        </li>
                        <li onclick="toggleSubmenu('HRM-4')">
                            <a href="javascript:void(0)" style="height: 48px;">
                                <span class="text">Employer_Services</span>
                                <i class='bx bx-chevron-down submenu-toggle'></i>
                            </a>
                            <ul id="HRM-4" class="submenu">
                                <li><a href="../Employer_Services/Attendance_manag/attend.html" target="contentFrame">Attendance Management</a></li>
                                <li><a href="../Employer_Services/Task_Allocation/Task.html" target="contentFrame">Task Allocation</a></li>
                                <li><a href="../Employer_Services/Shift_&_Rooster/Shift.html" target="contentFrame">Shift & Rooster</a></li>
                                <li><a href="../Employer_Services/Appraisal_to_Emp/Appraisal.html" target="contentFrame">Appraisal Software</a></li>
                                <li><a href="../Employer_Services/Leave_Approval/Leave.html" target="contentFrame">Leave Approval</a></li>
                                <li><a href="../Employer_Services/Notifications/Notification.html" target="contentFrame">Notification to Team</a></li>
                            </ul>
                        </li>
                    </ul>
                </li>
                <li onclick="toggleSubmenu('crm-submenu')">
                    <a href="javascript:void(0)" style="height: 48px;">
                        <i class="bx bx-money"></i>
                        <span class="text">CRM</span>
                        <i class='bx bx-chevron-down submenu-toggle'></i>
                    </a>
                    <ul id="crm-submenu" class="submenu">
                        <li><a href="../CRM/Strategic_CRM/Strategic.html" target="contentFrame">Strategic CRM</a></li>
                        <li><a href="../CRM/Analytical_CRM/Analytical.html" target="contentFrame">Analytical CRM</a></li>
                        <li><a href="../CRM/Operational_CRM/Oper.html" target="contentFrame">Operational CRM</a></li>
                        <li><a href="../CRM/Collaborative_CRM/Collaborative.html" target="contentFrame">Collaborative CRM</a></li>
                    </ul>
                </li>
                <li onclick="toggleSubmenu('analytics-submenu')">
                    <a href="javascript:void(0)" style="height: 48px;">
                        <i class='bx bx-line-chart'></i>
                        <span class="text">Analytics</span>
                        <i class='bx bx-chevron-down submenu-toggle'></i>
                    </a>
                    <ul id="analytics-submenu" class="submenu">
                        <li><a href="#">View Analytics</a></li>
                        <li><a href="#">Compare Stats</a></li>
                    </ul>
                </li>
                <li onclick="toggleSubmenu('apps-submenu')">
                    <a href="javascript:void(0)" style="height: 48px;">
                        <i class="bx bx-mobile-alt"></i>
                        <span class="text">Apps</span>
                        <i class='bx bx-chevron-down submenu-toggle'></i>
                    </a>
                    <ul id="apps-submenu" class="submenu">
                        <li><a href="#">Chats</a></li>
                        <li><a href="#">Email Inbox</a></li>
                        <li><a href="#">Contacts</a></li>
                        <li><a href="#">Calendar</a></li>
                    </ul>
                </li>
                <li onclick="toggleSubmenu('payroll-submenu')">
                    <a href="javascript:void(0)" style="height: 48px;">
                        <i class="bx bx-money"></i>
                        <span class="text">Payroll</span>
                        <i class='bx bx-chevron-down submenu-toggle'></i>
                    </a>
                    <ul id="payroll-submenu" class="submenu">
                        <li><a href="#">Payroll Overview</a></li>
                        <li><a href="#">Manage Payroll</a></li>
                    </ul>
                </li>
                <li onclick="toggleSubmenu('message-submenu')">
                    <a href="javascript:void(0)" style="height: 48px;">
                        <i class='bx bxs-message-dots'></i>
                        <span class="text">Expenses</span>
                        <i class='bx bx-chevron-down submenu-toggle'></i>
                    </a>
                    <ul id="message-submenu" class="submenu">
                        <li><a href="#">New Expense</a></li>
                        <li><a href="#">Expense Overview</a></li>
                    </ul>
                </li>
                <li onclick="toggleSubmenu('team-submenu')">
                    <a href="javascript:void(0)" style="height: 48px;">
                        <i class="bx bx-user-circle"></i>
                        <span class="text">Team</span>
                        <i class='bx bx-chevron-down submenu-toggle'></i>
                    </a>
                    <ul id="team-submenu" class="submenu">
                        <li><a href="#">View Team</a></li>
                        <li><a href="#">Add New Member</a></li>
                    </ul>
                </li>
                <li onclick="toggleSubmenu('Clients-submenu')">
                    <a href="javascript:void(0)" style="height: 48px;">
                        <i class='bx bx-briefcase'></i>
                        <span class="text">Clients</span>
                        <i class='bx bx-chevron-down submenu-toggle'></i>
                    </a>
                    <ul id="Clients-submenu" class="submenu">
                        <li><a href="#">Client A</a></li>
                        <li><a href="#">Client B</a></li>
                    </ul>
                </li>
                <li onclick="toggleSubmenu('projects-submenu')">
                    <a href="javascript:void(0)" style="height: 48px;">
                        <i class="bx bx-task"></i>
                        <span class="text">Projects</span>
                        <i class='bx bx-chevron-down submenu-toggle'></i>
                    </a>
                    <ul id="projects-submenu" class="submenu">
                        <li><a href="#">Project A</a></li>
                        <li><a href="#">Project B</a></li>
                    </ul>
                </li>
                <li onclick="toggleSubmenu('activities-submenu')">
                    <a href="javascript:void(0)" style="height: 48px;">
                        <i class='bx bx-calendar-event'></i>
                        <span class="text">Activities</span>
                        <i class='bx bx-chevron-down submenu-toggle'></i>
                    </a>
                    <ul id="activities-submenu" class="submenu">
                        <li><a href="#">Activity A</a></li>
                        <li><a href="#">Activity B</a></li>
                    </ul>
                </li>
            </ul>
            <ul class="side-menu" style="margin-top: 25px; border-radius: 10px; background: linear-gradient(to right, #4f8ff7, #a2c5f7);">
                <li>
                    <a href="#" style="height: 50px;">
                        <i class='bx bxs-cog'></i>
                        <span class="text">Settings</span>
                    </a>
                </li>
                <li>
                    <a href="#" class="logout" style="height: 50px;" onclick="logout()">
                        <i class='bx bxs-log-out-circle'></i>
                        <span class="text">Logout</span>
                    </a>
                </li>
            </ul>
        </section>
        <section style="width: 100%;">
            <iframe id="content-iframe" src="../Dashboard-Home/Home.html" name="contentFrame" style="width: 100%; height: 100%; border: none;"></iframe>
        </section>
    </div>
    <div class="notification-modal" id="logoutModal">
        <div class="notification-container">
            <div class="notification-icon animate-slide">
                <i class="bx bx-log-out-circle"></i>
            </div>
            <h3 class="notification-title animate-slide delay-100">Sign Out?</h3>
            <p class="notification-message animate-slide delay-200">Are you sure you want to sign out of your account?</p>
            <div class="notification-buttons animate-slide delay-300">
                <button class="btn-notification btn-cancel" onclick="closeLogoutModal()">Cancel</button>
                <button class="btn-notification btn-confirm" onclick="confirmLogout()">Sign Out</button>
            </div>
        </div>
    </div>
    <script>
        document.addEventListener('DOMContentLoaded', async function() {
            const token = localStorage.getItem('token'); // Check for token
            if (!token) {
                window.location.href = 'index.html'; // Redirect if no token
                return;
            }

            try {
                // Fetch user data from backend
                const response = await fetch('http://98.80.67.100:3017/api/user', {
                    method: 'GET',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    }
                });

                if (!response.ok) {
                    throw new Error('Failed to fetch user data');
                }

                const userData = await response.json();

                // Update username
                const usernameElements = document.querySelectorAll('#username, #firstusername');
                usernameElements.forEach(element => {
                    if (element) {
                        element.textContent = userData.username || 'User';
                    }
                });

                // Update profile image
                const profileImages = document.querySelectorAll('.profile-img');
                profileImages.forEach(img => {
                    if (img && userData.profileImage) {
                        img.src = `http://98.80.67.100:3017${userData.profileImage}`;
                        img.style.width = '70px';
                        img.style.height = '70px';
                        img.style.borderRadius = '50%';
                        img.style.objectFit = 'cover';
                    } else if (img) {
                        img.src = '../Assests/default-profile.jpg'; // Fallback image
                    }
                });

            } catch (error) {
                console.error('Error fetching user data:', error);
                localStorage.clear(); // Clear localStorage on error
                window.location.href = 'index.html'; // Redirect to index
            }

            // Dynamically add fadeOut keyframes
            const styleElement = document.createElement('style');
            const fadeOutKeyframes = `
                @keyframes fadeOut {
                    from { opacity: 1; transform: translate(-50%, -50%) scale(1); }
                    to { opacity: 0; transform: translate(-50%, -50%) scale(0.8); }
                }
            `;
            styleElement.textContent = fadeOutKeyframes;
            document.head.appendChild(styleElement);
        });

        function logout() {
            const modal = document.getElementById('logoutModal');
            modal.style.display = 'block';
            const animatedElements = document.querySelectorAll('.animate-slide');
            animatedElements.forEach(el => {
                el.style.animation = 'none';
                el.offsetHeight; // Trigger reflow
                el.style.animation = null;
            });
        }

        function closeLogoutModal() {
            const modal = document.getElementById('logoutModal');
            modal.style.display = 'none';
        }

        async function confirmLogout() {
            const container = document.querySelector('.notification-container');
            container.style.animation = 'fadeOut 0.3s ease-out forwards';
            
            // Notify backend to invalidate token (optional, if using token blacklist)
            try {
                const token = localStorage.getItem('token');
                await fetch('http://98.80.67.100:3017/api/logout', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    }
                });
            } catch (error) {
                console.error('Error notifying backend of logout:', error);
            }

            setTimeout(() => {
                // Clear all localStorage to ensure complete logout
                localStorage.clear();
                // Force navigation to index.html
                window.location.replace('http://98.80.67.100:9026/index.html'); 
            }, 300);
        }

        window.addEventListener('click', function(event) {
            const modal = document.getElementById('logoutModal');
            if (event.target === modal) {
                closeLogoutModal();
            }
        });

        document.querySelector('.profile-section').addEventListener('click', function() {
            const menu = document.querySelector('.profile-menu');
            menu.style.display = menu.style.display === 'block' ? 'none' : 'block';
            this.classList.toggle('active');
        });

        function toggleSubmenu(submenuId) {
            const submenu = document.getElementById(submenuId);
            const toggleIcon = submenu.previousElementSibling.querySelector('.submenu-toggle');
            submenu.style.display = submenu.style.display === 'block' ? 'none' : 'block';
            toggleIcon.classList.toggle('rotate');
        }

        document.querySelectorAll('.submenu li > a').forEach(submenuItem => {
            submenuItem.addEventListener('click', function (e) {
                e.stopPropagation();
                const parentLi = submenuItem.parentElement;
                const nestedSubmenu = parentLi.querySelector('.submenu');
                if (nestedSubmenu) {
                    nestedSubmenu.style.display = nestedSubmenu.style.display === 'block' ? 'none' : 'block';
                    const toggleIcon = parentLi.querySelector('.submenu-toggle');
                    if (toggleIcon) {
                        toggleIcon.classList.toggle('rotate');
                    }
                }
            });
        });

        function toggleCountryDropdown() {
            const dropdown = document.getElementById('countryDropdown');
            dropdown.style.display = (dropdown.style.display === 'block') ? 'none' : 'block';
        }

        document.addEventListener('click', function(event) {
            const dropdown = document.getElementById('countryDropdown');
            const languageSelector = document.querySelector('.language-selector');
            const globeIcon = document.querySelector('img[alt="geography--v2"]');
            if (!dropdown.contains(event.target) && !languageSelector.contains(event.target) && !globeIcon.contains(event.target)) {
                dropdown.style.display = 'none';
            }
        });

        const allSideMenu = document.querySelectorAll('#sidebar .side-menu.top li a');
        allSideMenu.forEach(item => {
            const li = item.parentElement;
            item.addEventListener('click', function () {
                allSideMenu.forEach(i => {
                    i.parentElement.classList.remove('active');
                });
                li.classList.add('active');
            });
        });

        const menuBar = document.querySelector('#content nav .bi.bi-chevron-compact-right');
        const sidebar = document.getElementById('sidebar');
        menuBar.addEventListener('click', function () {
            sidebar.classList.toggle('hide');
        });

        if (window.innerWidth < 768) {
            sidebar.classList.add('hide');
        }

        window.addEventListener('resize', function () {
            if (this.innerWidth > 576) {
                const searchButtonIcon = document.querySelector('#search-button');
                const searchForm = document.querySelector('#search-wrapper');
                if (searchButtonIcon && searchForm) {
                    searchButtonIcon.classList.replace('bx-x', 'bx-search');
                    searchForm.classList.remove('show');
                }
            }
        });

        function toggleFullscreen() {
            if (!document.fullscreenElement) {
                if (document.documentElement.requestFullscreen) {
                    document.documentElement.requestFullscreen();
                } else if (document.documentElement.mozRequestFullScreen) {
                    document.documentElement.mozRequestFullScreen();
                } else if (document.documentElement.webkitRequestFullscreen) {
                    document.documentElement.webkitRequestFullscreen();
                } else if (document.documentElement.msRequestFullscreen) {
                    document.documentElement.msRequestFullscreen();
                }
            } else {
                if (document.exitFullscreen) {
                    document.exitFullscreen();
                } else if (document.mozCancelFullScreen) {
                    document.mozCancelFullScreen();
                } else if (document.webkitExitFullscreen) {
                    document.webkitExitFullscreen();
                } else if (document.msExitFullscreen) {
                    document.msExitFullscreen();
                }
            }
        }

        const search = document.getElementById('search');
        search.addEventListener('focus', (event) => {
            document.getElementById('search-wrapper').style.border = "1px solid #1dbf73";
        });

        search.addEventListener('focusout', (event) => {
            document.getElementById('search-wrapper').style.border = "1px solid rgba(0, 0, 0, 0.276)";
        });
    </script>
</body>
</html>
