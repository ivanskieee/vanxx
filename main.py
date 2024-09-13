import os
from flask import Flask, render_template, redirect, url_for, request, session, flash, make_response
from werkzeug.utils import secure_filename
import sqlite3
import hashlib 

app = Flask(__name__)
UPLOAD_FOLDER = 'static/css/assets/images'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = 'your_secret_key'

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    if 'login_id' in session:
        if session.get('login_type') == '1':
            return redirect(url_for('home_admin'))
        if session.get('login_type') == '2':
            return redirect(url_for('home_faculty'))
        elif session.get('login_type') == '3':
            return redirect(url_for('home_student'))
    return render_template('login.html')

def verify_password(stored_password, provided_password):
    salt = bytes.fromhex(stored_password[:32])  # Extract the salt
    stored_hash = stored_password[32:]  # Extract the stored hash
    provided_hash = hashlib.sha256(salt + provided_password.encode('utf-8')).hexdigest()
    return stored_hash == provided_hash  # Compare the hashes

@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']
    login_type = request.form['login']
    remember = 'remember' in request.form

    conn = get_db_connection()
    user = None

    if login_type == '1':  # Admin
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    elif login_type == '2':  # Faculty
        user = conn.execute('SELECT * FROM faculty_list WHERE email = ?', (email,)).fetchone()
    elif login_type == '3':  # Student
        user = conn.execute('SELECT * FROM student_list WHERE email = ?', (email,)).fetchone()
    
    conn.close()

    if user and verify_password(user['password'], password):
        session['login_id'] = user['id']
        session['login_type'] = login_type
        session['avatar_path'] = user['avatar']  # Assuming the image URL is stored in the 'avatar_path' field

        resp = make_response(redirect(url_for(f'home_{["admin", "faculty", "student"][int(login_type) - 1]}')))
        if remember:
            resp.set_cookie('email', email, max_age=30*24*60*60)  # 30 days
            resp.set_cookie('password', password, max_age=30*24*60*60)  # 30 days
        else:
            resp.set_cookie('email', '', expires=0)
            resp.set_cookie('password', '', expires=0)
        return resp
    else:
        flash('Username or password is incorrect.', 'danger')
        return redirect(url_for('index'))

@app.route('/home_admin')
def home_admin():
    if 'login_id' not in session or session.get('login_type') != '1':
        return redirect(url_for('index'))
    
    conn = get_db_connection()

    # Calculate total counts
    total_students = conn.execute("SELECT COUNT(*) FROM student_list").fetchone()[0]
    total_faculty = conn.execute("SELECT COUNT(*) FROM faculty_list").fetchone()[0]
    total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    total_classes = conn.execute("SELECT COUNT(*) FROM class_list").fetchone()[0]

    conn.close()
    
    return render_template('admin/homeAdmin.html', total_students=total_students,
                           total_users=total_users, total_classes=total_classes, total_faculty=total_faculty, avatar_path=session.get('avatar_path'))

@app.route('/home_faculty')
def home_faculty():
    if 'login_id' not in session or session.get('login_type') != '2':
        return redirect(url_for('index'))
    return render_template('faculty/homeFaculty.html', avatar_path=session.get('avatar_path'))

@app.route('/home_student')
def home_student():
    if 'login_id' not in session or session.get('login_type') != '3':
        return redirect(url_for('index'))
    return render_template('student/homeStudent.html', avatar_path=session.get('avatar_path'))

@app.route('/evaluate')
def evaluate():
    if 'login_id' not in session or session.get('login_type') != '3':
        return redirect(url_for('index'))
    restriction_id = request.args.get('rid', '')
    faculty_id = request.args.get('fid', '')
    subject_id = request.args.get('sid', '')

    conn = get_db_connection()
    
    restrictions = conn.execute("""
        SELECT r.id, s.id as sid, f.id as fid, f.firstname || ' ' || f.lastname as faculty, s.code, s.subject 
        FROM restriction_list r 
        INNER JOIN faculty_list f ON f.id = r.faculty_id 
        INNER JOIN subject_list s ON s.id = r.subject_id 
        WHERE academic_id = ? AND class_id = ? 
        
    """, (session['academic_list']['id'], session['login_class_id'], session['academic_list']['id'], session['login_id'])).fetchall()

    if restrictions and not restriction_id:
        first_restriction = restrictions[0]
        restriction_id = first_restriction['id']
        faculty_id = first_restriction['fid']
        subject_id = first_restriction['sid']

    criteria = conn.execute("""
        SELECT * FROM criteria_list 
        WHERE id IN (
            SELECT criteria_id FROM question_list 
            WHERE academic_id = ?
        ) 
        ORDER BY abs(order_by) ASC
    """, (session['academic']['id'],)).fetchall()

    questions = {criterion['id']: conn.execute("""
        SELECT * FROM question_list 
        WHERE criteria_id = ? AND academic_id = ? 
        ORDER BY abs(order_by) ASC
    """, (criterion['id'], session['academic']['id'])).fetchall() for criterion in criteria}

    conn.close()

    return render_template('evaluation.html', restrictions=restrictions, criteria=criteria, questions=questions, restriction_id=restriction_id, faculty_id=faculty_id, subject_id=subject_id)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html', login_name='Admin')

@app.route('/subjects')
def subject_list():
    conn = get_db_connection()
    subjects = conn.execute("SELECT id, code, subject, description FROM subject_list").fetchall()
    conn.close()
    return render_template('admin/subject_list.html', subjects=subjects, avatar_path=session.get('avatar_path'))

@app.route('/subjects/new', methods=['GET', 'POST'])
@app.route('/subjects/<int:id>', methods=['GET', 'POST'])
def new_subject(id=None):
    conn = get_db_connection()
    subjects = None
    if id:
        subjects = conn.execute('SELECT * FROM subject_list WHERE id = ?', (id,)).fetchone()

    if request.method == 'POST':
        code = request.form['code']
        subject = request.form['subject']
        description = request.form['description']

        if id:
            query = '''
                UPDATE subject_list SET code = ?, subject = ?, description = ? WHERE id = ?
            '''
            conn.execute(query, (code, subject, description, id))
        else:
            query = '''
                INSERT INTO subject_list (code, subject, description)
                VALUES (?, ?, ?)
            '''
            conn.execute(query, (code, subject, description))
        
        conn.commit()
        conn.close()

        flash('Data successfully saved.', 'success')
        return redirect(url_for('subject_list'))

    conn.close()
    return render_template('admin/new_subject.html', subjects=subjects, avatar_path=session.get('avatar_path'))


@app.route('/delete_subject/<int:id>', methods=['POST'])
def delete_subject(id):
    conn = get_db_connection()
    conn.execute('DELETE FROM subject_list WHERE id=?', (id,))
    conn.commit()
    conn.close()
    flash('Subject deleted successfully', 'success')
    return redirect(url_for('subject_list'))

@app.route('/classes')
def class_list():
    conn = get_db_connection()
    classes = conn.execute("SELECT id, curriculum, level, section FROM class_list").fetchall()
    conn.close()
    return render_template('admin/class_list.html', classes=classes, avatar_path=session.get('avatar_path'))

@app.route('/classes/new', methods=['GET', 'POST'])
@app.route('/classes/<int:id>', methods=['GET', 'POST'])
def new_class(id=None):
    conn = get_db_connection()
    classes = None
    if id:
        classes = conn.execute('SELECT * FROM class_list WHERE id = ?', (id,)).fetchone()

    if request.method == 'POST':
        curriculum = request.form['curriculum']
        level = request.form['level']
        section = request.form['section']

        if id:
            query = '''
                UPDATE class_list SET curriculum = ?, level = ?, section = ? WHERE id = ?
            '''
            conn.execute(query, (curriculum, level, section, id))
        else:
            query = '''
                INSERT INTO class_list (curriculum, level, section)
                VALUES (?, ?, ?)
            '''
            conn.execute(query, (curriculum, level, section))
        
        conn.commit()
        conn.close()

        flash('Data successfully saved.', 'success')
        return redirect(url_for('class_list'))

    conn.close()
    return render_template('admin/new_class.html', classes=classes, avatar_path=session.get('avatar_path'))

@app.route('/delete_class/<int:id>', methods=['POST'])
def delete_class(id):
    conn = get_db_connection()
    conn.execute('DELETE FROM class_list WHERE id=?', (id,))
    conn.commit()
    conn.close()
    flash('Class deleted successfully', 'success')
    return redirect(url_for('class_list'))

@app.route('/academic/new', methods=['GET', 'POST'])
@app.route('/academic/<int:id>', methods=['GET', 'POST'])
def new_academic(id=None):
    conn = get_db_connection()
    academic = None
    if id:
        academic = conn.execute('SELECT * FROM academic_list WHERE id = ?', (id,)).fetchone()

    if request.method == 'POST':
        year = request.form['year']
        semester = request.form['semester']
        is_default = request.form['is_default']
        status = request.form['status']

        if id:
            query = '''
                UPDATE academic_list SET year = ?, semester = ?, is_default = ?, status = ? WHERE id = ?
            '''
            conn.execute(query, (year, semester, is_default, status, id))
        else:
            query = '''
                INSERT INTO academic_list (year, semester, is_default, status)
                VALUES (?, ?, ?, ?)
            '''
            conn.execute(query, (year, semester, is_default, status))

        conn.commit()
        conn.close()

        flash('Data successfully saved.', 'success')
        return redirect(url_for('academic_list'))

    conn.close()
    return render_template('admin/new_academic.html', academic=academic, avatar_path=session.get('avatar_path'))

@app.route('/academic-year')
def academic_list():
    conn = get_db_connection()
    academic = conn.execute('SELECT id, year, semester, is_default, status FROM academic_list').fetchall()
    conn.close()
    return render_template('admin/academic_list.html', academic=academic, avatar_path=session.get('avatar_path'))

@app.route('/delete_academic/<int:id>', methods=['POST'])
def delete_academic(id):
    conn = get_db_connection()
    conn.execute('DELETE FROM academic_list WHERE id=?', (id,))
    conn.commit()
    conn.close()
    flash('Data deleted successfully', 'success')
    return redirect(url_for('academic_list'))

@app.route('/questionnaire/new', methods=['GET', 'POST'])
@app.route('/questionnaire/<int:id>', methods=['GET', 'POST'])
def new_question(id=None):
    conn = get_db_connection()
    if id:
        question_data = conn.execute('SELECT * FROM question_list WHERE id = ?', (id,)).fetchone()
    else:
        question_data = None

    if request.method == 'POST':
        academic_id = request.form['academic_id']
        question = request.form['question']
        order_by = request.form['order_by']
        criteria_id = request.form['criteria_id']

        if id:  # If question_id exists, update the existing question
            query = '''
                UPDATE question_list
                SET academic_id = ?, question = ?, order_by = ?, criteria_id = ?
                WHERE id = ?
            '''
            conn.execute(query, (academic_id, question, order_by, criteria_id, id))
            flash('Question successfully updated.', 'success')
        else:  # Otherwise, insert a new question
            query = '''
                INSERT INTO question_list (academic_id, question, order_by, criteria_id)
                VALUES (?, ?, ?, ?)
            '''
            conn.execute(query, (academic_id, question, order_by, criteria_id))
            flash('Question successfully added.', 'success')

        conn.commit()
        conn.close()
        
        return redirect(url_for('questionnaire'))

    faculty_list = conn.execute('SELECT id, school_id, firstname, lastname FROM faculty_list').fetchall()
    criteria_list = conn.execute('SELECT id, criteria FROM criteria_list').fetchall()
    academic_list = conn.execute('SELECT id, year, semester FROM academic_list ORDER BY abs(year) DESC, abs(semester) DESC').fetchall()
    conn.close()


    return render_template('admin/new_question.html', academic_list=academic_list, faculty_list=faculty_list, criteria_list=criteria_list, question_data=question_data, avatar_path=session.get('avatar_path'))

@app.route('/questionnaire')
def questionnaire():
    conn = get_db_connection()
    questionnaire = conn.execute('SELECT id, academic_id, question, order_by, criteria_id FROM question_list').fetchall()
    conn.close()
    return render_template('admin/questionnaire.html', questionnaire=questionnaire, avatar_path=session.get('avatar_path'))

@app.route('/delete_questionnaire/<int:id>', methods=['POST'])
def delete_questionnaire(id):
    conn = get_db_connection()
    conn.execute('DELETE FROM question_list WHERE id=?', (id,))
    conn.commit()
    conn.close()
    flash('Question deleted successfully', 'success')
    return redirect(url_for('questionnaire'))

@app.route('/new_criteria/new', methods=['GET', 'POST'])
@app.route('/new_criteria/<int:id>', methods=['GET', 'POST'])
def new_criteria(id=None):
    conn = get_db_connection()
    criteria = None

    if id is not None:
        criteria = conn.execute('SELECT * FROM criteria_list WHERE id = ?', (id,)).fetchone()

    if request.method == 'POST':
        criteria_text = request.form['criteria']
        order_by = request.form['order_by']

        if id is not None:
            query = '''
                UPDATE criteria_list SET criteria = ?, order_by = ?
                WHERE id = ?
            '''
            conn.execute(query, (criteria_text, order_by, id))
        else:
            query = '''
                INSERT INTO criteria_list (criteria, order_by)
                VALUES (?, ?)
            '''
            conn.execute(query, (criteria_text, order_by))
        
        conn.commit()
        conn.close()

        flash('Data successfully saved.', 'success')
        return redirect(url_for('criteria_list'))
    
    faculty_list = conn.execute('SELECT id, school_id, firstname, lastname FROM faculty_list').fetchall()
    conn.close()
    return render_template('admin/new_criteria.html', criteria=criteria, faculty_list=faculty_list, avatar_path=session.get('avatar_path'))


@app.route('/criteria')
def criteria_list():
    conn = get_db_connection()
    criterias = conn.execute("SELECT id, criteria, order_by FROM criteria_list").fetchall()
    conn.close()
    return render_template('admin/criteria_list.html', criterias=criterias, avatar_path=session.get('avatar_path'))

@app.route('/delete_criteria/<int:id>', methods=['POST'])
def delete_criteria(id):
    conn = get_db_connection()
    conn.execute('DELETE FROM criteria_list WHERE id=?', (id,))
    conn.commit()
    conn.close()
    flash('Data deleted successfully', 'success')
    return redirect(url_for('criteria_list'))

@app.route('/faculty/new', methods=['GET', 'POST'])
@app.route('/faculty/<int:id>', methods=['GET', 'POST'])
def new_faculty(id=None):
    conn = get_db_connection()
    faculty = None
    if id:
        faculty = conn.execute('SELECT * FROM faculty_list WHERE id = ?', (id,)).fetchone()

    if request.method == 'POST':
        school_id = request.form['school_id']
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        email = request.form['email']
        password = request.form['password']
        cpass = request.form['cpass']
        avatar = request.files['img'].filename if 'img' in request.files else None

        if password and password != cpass:
            flash('Passwords do not match', 'danger')
            return redirect(request.url)

        if id:
            query = '''
                UPDATE faculty_list SET school_id = ?, firstname = ?, lastname = ?, email = ?, password = ?, avatar = ?
                WHERE id = ?
            '''
            conn.execute(query, (school_id, firstname, lastname, email, password, avatar, id))
        else:
            query = '''
                INSERT INTO faculty_list (school_id, firstname, lastname, email, password, avatar)
                VALUES (?, ?, ?, ?, ?, ?)
            '''
            conn.execute(query, (school_id, firstname, lastname, email, password, avatar))
        
        conn.commit()
        conn.close()

        flash('Data successfully saved.', 'success')
        return redirect(url_for('faculty_list'))

    conn.close()
    return render_template('admin/new_faculty.html', faculty=faculty, avatar_path=session.get('avatar_path'))

@app.route('/faculty')
def faculty_list():
    conn = get_db_connection()
    faculties = conn.execute("SELECT id, school_id, firstname, lastname, email FROM faculty_list").fetchall()
    conn.close()
    return render_template('admin/faculty_list.html', faculties=faculties, avatar_path=session.get('avatar_path'))

@app.route('/delete_faculty/<int:id>', methods=['GET', 'POST'])
def delete_faculty(id):
    conn = get_db_connection()
    conn.execute('DELETE FROM faculty_list WHERE id=?', (id,))
    conn.commit()
    conn.close()
    flash('Faculty deleted successfully', 'success')
    return redirect(url_for('faculty_list'))

@app.route('/students/new', methods=['GET', 'POST'])
@app.route('/students/<int:id>', methods=['GET', 'POST'])
def new_student(id=None):
    conn = get_db_connection()
    student = None
    classes = conn.execute('SELECT id, curriculum || " " || level || " - " || section AS class FROM class_list').fetchall()
    
    if id:
        student = conn.execute('SELECT * FROM student_list WHERE id = ?', (id,)).fetchone()

    if request.method == 'POST':
        school_id = request.form['school_id']
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        class_id = request.form['class_id']
        email = request.form['email']
        password = request.form['password']
        cpass = request.form['cpass']
        avatar = request.files['img'].filename if 'img' in request.files else None

        if password and password != cpass:
            flash('Passwords do not match', 'danger')
            return redirect(request.url)

        if id:
            query = '''
                UPDATE student_list SET school_id = ?, firstname = ?, lastname = ?, class_id = ?, email = ?, password = ?, avatar = ?
                WHERE id = ?
            '''
            conn.execute(query, (school_id, firstname, lastname, class_id, email, password, avatar, id))
        else:
            query = '''
                INSERT INTO student_list (school_id, firstname, lastname, class_id, email, password, avatar)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            '''
            conn.execute(query, (school_id, firstname, lastname, class_id, email, password, avatar))
        
        conn.commit()
        conn.close()

        flash('Data successfully saved.', 'success')
        return redirect(url_for('student_list'))
    
    return render_template('admin/new_student.html', student=student, classes=classes, avatar_path=session.get('avatar_path'))

@app.route('/students')
def student_list():
    conn = get_db_connection()
    classes = {}
    class_list = conn.execute("SELECT id, curriculum, level, section FROM class_list").fetchall()
    for c in class_list:
        classes[c['id']] = f"{c['curriculum']} {c['level']} - {c['section']}"
    
    students = conn.execute("SELECT id, school_id, firstname, lastname, email, class_id FROM student_list").fetchall()
    conn.close()
    return render_template('admin/student_list.html', students=students, classes=classes, avatar_path=session.get('avatar_path'))

@app.route('/delete_student/<int:id>', methods=['POST', 'GET'])
def delete_student(id):
    if request.method == 'POST':
        conn = get_db_connection()
        conn.execute('DELETE FROM student_list WHERE id=?', (id,))
        conn.commit()
        conn.close()
        flash('Student deleted successfully', 'success')
        return redirect(url_for('student_list'))

@app.route('/report')
def report():
    return render_template('admin/report.html', avatar_path=session.get('avatar_path'))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def hash_password(password):
    salt = os.urandom(16)  # Generate a random salt
    hashed_password = hashlib.sha256(salt + password.encode('utf-8')).hexdigest()
    return salt.hex() + hashed_password  # Store salt and hashed password together

@app.route('/users/new', methods=['GET', 'POST'])
@app.route('/users/<int:id>', methods=['GET', 'POST'])
def new_user(id=None):
    conn = get_db_connection()
    user = None
    if id:
        user = conn.execute('SELECT * FROM users WHERE id = ?', (id,)).fetchone()

    if request.method == 'POST':
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        email = request.form['email']
        password = request.form['password']
        cpass = request.form['cpass']
        
        # Handling avatar upload
        if 'img' in request.files:
            img = request.files['img']
            if img.filename != '' and allowed_file(img.filename):
                filename = secure_filename(img.filename)
                img.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                avatar = filename
            else:
                avatar = 'default_avatar.jpg'  # Default avatar if no valid file uploaded
        else:
            avatar = 'default_avatar.jpg'  # Default avatar if no file field in form

        if password and password != cpass:
            flash('Passwords do not match', 'danger')
            return redirect(request.url)

        # Hash the password before storing it
        hashed_password = hash_password(password)

        if id:
            query = '''
                UPDATE users SET firstname = ?, lastname = ?, email = ?, password = ?, avatar = ?
                WHERE id = ?
            '''
            conn.execute(query, (firstname, lastname, email, hashed_password, avatar, id))
        else:
            query = '''
                INSERT INTO users (firstname, lastname, email, password, avatar)
                VALUES (?, ?, ?, ?, ?)
            '''
            conn.execute(query, (firstname, lastname, email, hashed_password, avatar))
        
        conn.commit()
        conn.close()

        flash('Data successfully saved.', 'success')
        return redirect(url_for('user_list'))

    conn.close()
    return render_template('admin/new_user.html', user=user, avatar_path=session.get('avatar_path'))

@app.route('/avatar')
def avatar():
    conn = get_db_connection()
    user_id = 1  # Example user ID
    user = conn.execute('SELECT * FROM users WHERE id = ?', [user_id], one=True)
    avatar_path = user['avatar_path'] if user and 'avatar_path' in user else 'css/assets/images/default_avatar.jpg'
    return render_template('avatar.html', avatar_path=avatar_path,)

@app.route('/users')
def user_list():
    conn = get_db_connection()
    users = conn.execute("SELECT id, firstname, lastname, email FROM users").fetchall()
    conn.close()
    return render_template('admin/user_list.html', users=users, avatar_path=session.get('avatar_path'))

@app.route('/delete_user/<int:id>', methods=['POST', 'GET'])
def delete_user(id):
    if request.method == 'POST':
        conn = get_db_connection()
        conn.execute('DELETE FROM users WHERE id=?', (id,))
        conn.commit()
        conn.close()
        flash('User deleted successfully', 'success')
        return redirect(url_for('user_list'))
    
@app.route('/homeadminchart')
def homeadminchart():
    return render_template('admin/homeadminchart.html', avatar_path=session.get('avatar_path'))

if __name__ == '__main__':
    app.run(debug=True)
