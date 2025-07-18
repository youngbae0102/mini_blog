from flask import Flask, request, render_template, redirect, url_for, abort, flash, send_file, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
import os
import pymysql
import uuid
from datetime import datetime

# .env 파일 로드
load_dotenv(dotenv_path='/var/www/mini_blog/.env')

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")

# 파일 업로드 설정
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'txt', 'doc', 'docx', 'zip'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Flask-Login 초기화
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

def get_db_connection():
    return pymysql.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME"),
        cursorclass=pymysql.cursors.DictCursor
    )

class User(UserMixin):
    def __init__(self, id, username, password_hash, bio=None, created_at=None):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.bio = bio
        self.created_at = created_at

    @staticmethod
    def get(user_id):
        conn = get_db_connection()
        with conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
                user = cursor.fetchone()
                if user:
                    return User(
                        user['id'], 
                        user['username'], 
                        user['password_hash'],
                        user.get('bio'),
                        user.get('created_at')
                    )
        return None

    @staticmethod
    def get_by_username(username):
        conn = get_db_connection()
        with conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
                user = cursor.fetchone()
                if user:
                    return User(
                        user['id'], 
                        user['username'], 
                        user['password_hash'],
                        user.get('bio'),
                        user.get('created_at')
                    )
        return None

    def get_posts(self, limit=None):
        conn = get_db_connection()
        with conn:
            with conn.cursor() as cursor:
                if limit:
                    cursor.execute("""
                        SELECT 
                            p.id, 
                            p.title, 
                            p.created_at,
                            COALESCE(likes.count, 0) as like_count,
                            COALESCE(dislikes.count, 0) as dislike_count
                        FROM posts p
                        LEFT JOIN (
                            SELECT post_id, COUNT(*) as count 
                            FROM post_reactions 
                            WHERE reaction_type = 'like' 
                            GROUP BY post_id
                        ) likes ON p.id = likes.post_id
                        LEFT JOIN (
                            SELECT post_id, COUNT(*) as count 
                            FROM post_reactions 
                            WHERE reaction_type = 'dislike' 
                            GROUP BY post_id
                        ) dislikes ON p.id = dislikes.post_id
                        WHERE p.user_id = %s 
                        ORDER BY p.created_at DESC 
                        LIMIT %s
                    """, (self.id, limit))
                else:
                    cursor.execute("""
                        SELECT 
                            p.id, 
                            p.title, 
                            p.created_at,
                            COALESCE(likes.count, 0) as like_count,
                            COALESCE(dislikes.count, 0) as dislike_count
                        FROM posts p
                        LEFT JOIN (
                            SELECT post_id, COUNT(*) as count 
                            FROM post_reactions 
                            WHERE reaction_type = 'like' 
                            GROUP BY post_id
                        ) likes ON p.id = likes.post_id
                        LEFT JOIN (
                            SELECT post_id, COUNT(*) as count 
                            FROM post_reactions 
                            WHERE reaction_type = 'dislike' 
                            GROUP BY post_id
                        ) dislikes ON p.id = dislikes.post_id
                        WHERE p.user_id = %s 
                        ORDER BY p.created_at DESC
                    """, (self.id,))
                return cursor.fetchall()

    def get_post_count(self):
        conn = get_db_connection()
        with conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT COUNT(*) as count FROM posts WHERE user_id = %s", (self.id,))
                return cursor.fetchone()['count']

    def update_profile(self, bio):
        conn = get_db_connection()
        with conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "UPDATE users SET bio = %s WHERE id = %s",
                    (bio, self.id)
                )
                conn.commit()
                self.bio = bio
                return True

class Comment:
    def __init__(self, id, post_id, user_id, content, created_at, username=None):
        self.id = id
        self.post_id = post_id
        self.user_id = user_id
        self.content = content
        self.created_at = created_at
        self.username = username

    @staticmethod
    def get_by_post_id(post_id):
        conn = get_db_connection()
        with conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT c.*, u.username 
                    FROM comments c 
                    JOIN users u ON c.user_id = u.id 
                    WHERE c.post_id = %s 
                    ORDER BY c.created_at ASC
                """, (post_id,))
                comments = cursor.fetchall()
                return [Comment(
                    comment['id'],
                    comment['post_id'],
                    comment['user_id'],
                    comment['content'],
                    comment['created_at'],
                    comment['username']
                ) for comment in comments]

    @staticmethod
    def create(post_id, user_id, content):
        conn = get_db_connection()
        with conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO comments (post_id, user_id, content) VALUES (%s, %s, %s)",
                    (post_id, user_id, content)
                )
                conn.commit()
                return cursor.lastrowid

    @staticmethod
    def delete(comment_id, user_id):
        conn = get_db_connection()
        with conn:
            with conn.cursor() as cursor:
                cursor.execute("DELETE FROM comments WHERE id = %s AND user_id = %s", (comment_id, user_id))
                conn.commit()
                return cursor.rowcount > 0

class Upload:
    def __init__(self, id, filename, original_filename, file_path, file_size, mime_type, uploaded_by, uploaded_at):
        self.id = id
        self.filename = filename
        self.original_filename = original_filename
        self.file_path = file_path
        self.file_size = file_size
        self.mime_type = mime_type
        self.uploaded_by = uploaded_by
        self.uploaded_at = uploaded_at

    @staticmethod
    def create(filename, original_filename, file_path, file_size, mime_type, uploaded_by):
        conn = get_db_connection()
        with conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO uploads (filename, original_filename, file_path, file_size, mime_type, uploaded_by) VALUES (%s, %s, %s, %s, %s, %s)",
                    (filename, original_filename, file_path, file_size, mime_type, uploaded_by)
                )
                conn.commit()
                return cursor.lastrowid

    @staticmethod
    def get(upload_id):
        conn = get_db_connection()
        with conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT * FROM uploads WHERE id = %s", (upload_id,))
                upload = cursor.fetchone()
                if upload:
                    return Upload(
                        upload['id'],
                        upload['filename'],
                        upload['original_filename'],
                        upload['file_path'],
                        upload['file_size'],
                        upload['mime_type'],
                        upload['uploaded_by'],
                        upload['uploaded_at']
                    )
        return None

    @staticmethod
    def get_by_post_id(post_id):
        conn = get_db_connection()
        with conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT u.* FROM uploads u
                    JOIN post_files pf ON u.id = pf.upload_id
                    WHERE pf.post_id = %s
                """, (post_id,))
                uploads = cursor.fetchall()
                return [Upload(
                    upload['id'],
                    upload['filename'],
                    upload['original_filename'],
                    upload['file_path'],
                    upload['file_size'],
                    upload['mime_type'],
                    upload['uploaded_by'],
                    upload['uploaded_at']
                ) for upload in uploads]

    @staticmethod
    def attach_to_post(post_id, upload_id):
        conn = get_db_connection()
        with conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO post_files (post_id, upload_id) VALUES (%s, %s)",
                    (post_id, upload_id)
                )
                conn.commit()

class PostReaction:
    def __init__(self, id, post_id, user_id, reaction_type, created_at):
        self.id = id
        self.post_id = post_id
        self.user_id = user_id
        self.reaction_type = reaction_type
        self.created_at = created_at

    @staticmethod
    def add_or_update_reaction(post_id, user_id, reaction_type):
        conn = get_db_connection()
        with conn:
            with conn.cursor() as cursor:
                # 기존 반응이 있는지 확인
                cursor.execute(
                    "SELECT * FROM post_reactions WHERE post_id = %s AND user_id = %s",
                    (post_id, user_id)
                )
                existing_reaction = cursor.fetchone()
                
                if existing_reaction:
                    if existing_reaction['reaction_type'] == reaction_type:
                        # 같은 반응이면 삭제 (토글)
                        cursor.execute(
                            "DELETE FROM post_reactions WHERE post_id = %s AND user_id = %s",
                            (post_id, user_id)
                        )
                        action = 'removed'
                    else:
                        # 다른 반응이면 업데이트
                        cursor.execute(
                            "UPDATE post_reactions SET reaction_type = %s WHERE post_id = %s AND user_id = %s",
                            (reaction_type, post_id, user_id)
                        )
                        action = 'updated'
                else:
                    # 새로운 반응 추가
                    cursor.execute(
                        "INSERT INTO post_reactions (post_id, user_id, reaction_type) VALUES (%s, %s, %s)",
                        (post_id, user_id, reaction_type)
                    )
                    action = 'added'
                
                conn.commit()
                return action

    @staticmethod
    def get_reaction_counts(post_id):
        conn = get_db_connection()
        with conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT 
                        reaction_type,
                        COUNT(*) as count
                    FROM post_reactions 
                    WHERE post_id = %s 
                    GROUP BY reaction_type
                """, (post_id,))
                results = cursor.fetchall()
                
                counts = {'like': 0, 'dislike': 0}
                for result in results:
                    counts[result['reaction_type']] = result['count']
                
                return counts

    @staticmethod
    def get_user_reaction(post_id, user_id):
        if not user_id:
            return None
        
        conn = get_db_connection()
        with conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT reaction_type FROM post_reactions WHERE post_id = %s AND user_id = %s",
                    (post_id, user_id)
                )
                result = cursor.fetchone()
                return result['reaction_type'] if result else None

    @staticmethod
    def get_posts_with_reaction_counts():
        conn = get_db_connection()
        with conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT 
                        p.id,
                        p.title,
                        p.created_at,
                        COALESCE(likes.count, 0) as like_count,
                        COALESCE(dislikes.count, 0) as dislike_count
                    FROM posts p
                    LEFT JOIN (
                        SELECT post_id, COUNT(*) as count 
                        FROM post_reactions 
                        WHERE reaction_type = 'like' 
                        GROUP BY post_id
                    ) likes ON p.id = likes.post_id
                    LEFT JOIN (
                        SELECT post_id, COUNT(*) as count 
                        FROM post_reactions 
                        WHERE reaction_type = 'dislike' 
                        GROUP BY post_id
                    ) dislikes ON p.id = dislikes.post_id
                    ORDER BY p.created_at DESC
                """)
                return cursor.fetchall()

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

@app.route('/')
def index():
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')
    per_page = 5  # 페이지당 게시글 수
    
    conn = get_db_connection()
    with conn:
        with conn.cursor() as cursor:
            if search:
                # 검색어가 있을 때
                search_query = f"%{search}%"
                cursor.execute("SELECT COUNT(*) as total FROM posts WHERE title LIKE %s OR content LIKE %s", 
                             (search_query, search_query))
                total_posts = cursor.fetchone()['total']
                
                offset = (page - 1) * per_page
                cursor.execute("""
                    SELECT 
                        p.id, 
                        p.title, 
                        p.created_at,
                        COALESCE(likes.count, 0) as like_count,
                        COALESCE(dislikes.count, 0) as dislike_count
                    FROM posts p
                    LEFT JOIN (
                        SELECT post_id, COUNT(*) as count 
                        FROM post_reactions 
                        WHERE reaction_type = 'like' 
                        GROUP BY post_id
                    ) likes ON p.id = likes.post_id
                    LEFT JOIN (
                        SELECT post_id, COUNT(*) as count 
                        FROM post_reactions 
                        WHERE reaction_type = 'dislike' 
                        GROUP BY post_id
                    ) dislikes ON p.id = dislikes.post_id
                    WHERE p.title LIKE %s OR p.content LIKE %s 
                    ORDER BY p.created_at DESC 
                    LIMIT %s OFFSET %s
                """, (search_query, search_query, per_page, offset))
                posts = cursor.fetchall()
            else:
                # 전체 게시글 조회
                cursor.execute("SELECT COUNT(*) as total FROM posts")
                total_posts = cursor.fetchone()['total']
                
                offset = (page - 1) * per_page
                cursor.execute("""
                    SELECT 
                        p.id, 
                        p.title, 
                        p.created_at,
                        COALESCE(likes.count, 0) as like_count,
                        COALESCE(dislikes.count, 0) as dislike_count
                    FROM posts p
                    LEFT JOIN (
                        SELECT post_id, COUNT(*) as count 
                        FROM post_reactions 
                        WHERE reaction_type = 'like' 
                        GROUP BY post_id
                    ) likes ON p.id = likes.post_id
                    LEFT JOIN (
                        SELECT post_id, COUNT(*) as count 
                        FROM post_reactions 
                        WHERE reaction_type = 'dislike' 
                        GROUP BY post_id
                    ) dislikes ON p.id = dislikes.post_id
                    ORDER BY p.created_at DESC 
                    LIMIT %s OFFSET %s
                """, (per_page, offset))
                posts = cursor.fetchall()
    
    # 페이지네이션 정보 계산
    total_pages = (total_posts + per_page - 1) // per_page if total_posts > 0 else 1
    has_prev = page > 1
    has_next = page < total_pages
    
    return render_template('index.html', 
                         posts=posts,
                         page=page,
                         total_pages=total_pages,
                         has_prev=has_prev,
                         has_next=has_next,
                         search=search)

@app.route('/post/<int:post_id>')
def post(post_id):
    conn = get_db_connection()
    with conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM posts WHERE id = %s", (post_id,))
            post = cursor.fetchone()
    if post is None:
        abort(404)
    
    # 댓글 불러오기
    comments = Comment.get_by_post_id(post_id)
    
    # 첨부파일 불러오기
    uploads = Upload.get_by_post_id(post_id)
    
    # 좋아요/싫어요 정보 불러오기
    reaction_counts = PostReaction.get_reaction_counts(post_id)
    user_reaction = PostReaction.get_user_reaction(post_id, current_user.id if current_user.is_authenticated else None)
    
    return render_template('post.html', 
                         post=post, 
                         comments=comments, 
                         uploads=uploads,
                         reaction_counts=reaction_counts,
                         user_reaction=user_reaction)

@app.route('/write', methods=['GET', 'POST'])
@login_required
def write():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        
        conn = get_db_connection()
        with conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO posts (title, content, user_id) VALUES (%s, %s, %s)",
                    (title, content, current_user.id)
                )
                conn.commit()
                post_id = cursor.lastrowid
                
                # 파일 업로드 처리
                uploaded_files = request.files.getlist('files')
                for file in uploaded_files:
                    if file and file.filename != '' and allowed_file(file.filename):
                        # 안전한 파일명 생성
                        original_filename = secure_filename(file.filename)
                        filename = str(uuid.uuid4()) + '_' + original_filename
                        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        
                        # 파일 저장
                        file.save(file_path)
                        
                        # 파일 정보 DB에 저장
                        file_size = os.path.getsize(file_path)
                        upload_id = Upload.create(
                            filename=filename,
                            original_filename=original_filename,
                            file_path=file_path,
                            file_size=file_size,
                            mime_type=file.content_type or 'application/octet-stream',
                            uploaded_by=current_user.id
                        )
                        
                        # 게시글과 파일 연결
                        Upload.attach_to_post(post_id, upload_id)
                
        return redirect(url_for('index'))
    return render_template('write.html')

@app.route('/edit/<int:post_id>', methods=['GET', 'POST'])
@login_required
def edit(post_id):
    conn = get_db_connection()
    with conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM posts WHERE id = %s", (post_id,))
            post = cursor.fetchone()
            if not post:
                abort(404)
            if request.method == 'POST':
                new_title = request.form['title']
                new_content = request.form['content']
                cursor.execute(
                    "UPDATE posts SET title = %s, content = %s WHERE id = %s",
                    (new_title, new_content, post_id)
                )
                conn.commit()
                return redirect(url_for('post', post_id=post_id))
    return render_template('edit.html', post=post)

@app.route('/delete/<int:post_id>', methods=['POST'])
@login_required
def delete(post_id):
    conn = get_db_connection()
    with conn:
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM posts WHERE id = %s", (post_id,))
            conn.commit()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        pw_hash = generate_password_hash(password)

        conn = get_db_connection()
        with conn:
            with conn.cursor() as cursor:
                try:
                    cursor.execute(
                        "INSERT INTO users (username, password_hash) VALUES (%s, %s)",
                        (username, pw_hash)
                    )
                    conn.commit()
                    flash('회원가입 성공! 로그인 해주세요.')
                    return redirect(url_for('login'))
                except:
                    flash('이미 존재하는 사용자 이름입니다.')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        with conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
                user = cursor.fetchone()

                if user and check_password_hash(user['password_hash'], password):
                    user_obj = User(user['id'], user['username'], user['password_hash'])
                    login_user(user_obj)
                    flash('로그인 성공!')
                    return redirect(url_for('index'))
                else:
                    flash('아이디 또는 비밀번호가 올바르지 않습니다.')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('로그아웃 되었습니다.')
    return redirect(url_for('index'))

@app.route('/comment/<int:post_id>', methods=['POST'])
@login_required
def add_comment(post_id):
    content = request.form.get('content')
    if content and content.strip():
        Comment.create(post_id, current_user.id, content.strip())
        flash('댓글이 작성되었습니다.')
    else:
        flash('댓글 내용을 입력해주세요.')
    return redirect(url_for('post', post_id=post_id))

@app.route('/comment/delete/<int:comment_id>', methods=['POST'])
@login_required
def delete_comment(comment_id):
    if Comment.delete(comment_id, current_user.id):
        flash('댓글이 삭제되었습니다.')
    else:
        flash('댓글을 삭제할 수 없습니다.')
    
    # 이전 페이지로 리디렉션
    return redirect(request.referrer or url_for('index'))

@app.route('/download/<int:upload_id>')
def download_file(upload_id):
    upload = Upload.get(upload_id)
    if not upload:
        abort(404)
    
    try:
        return send_file(
            upload.file_path,
            as_attachment=True,
            download_name=upload.original_filename
        )
    except FileNotFoundError:
        flash('파일을 찾을 수 없습니다.')
        return redirect(request.referrer or url_for('index'))

@app.route('/view/<int:upload_id>')
def view_file(upload_id):
    upload = Upload.get(upload_id)
    if not upload:
        abort(404)
    
    # 이미지 파일인 경우에만 브라우저에서 바로 보기
    if upload.mime_type.startswith('image/'):
        try:
            return send_file(upload.file_path)
        except FileNotFoundError:
            flash('파일을 찾을 수 없습니다.')
            return redirect(request.referrer or url_for('index'))
    else:
        # 이미지가 아닌 경우 다운로드로 처리
        return download_file(upload_id)

@app.route('/api/post/<int:post_id>/reaction', methods=['POST'])
@login_required
def toggle_reaction(post_id):
    try:
        data = request.get_json()
        reaction_type = data.get('reaction_type')
        
        if reaction_type not in ['like', 'dislike']:
            return jsonify({'error': 'Invalid reaction type'}), 400
        
        # 게시글 존재 확인
        conn = get_db_connection()
        with conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT id FROM posts WHERE id = %s", (post_id,))
                if not cursor.fetchone():
                    return jsonify({'error': 'Post not found'}), 404
        
        # 반응 추가/업데이트/삭제
        action = PostReaction.add_or_update_reaction(post_id, current_user.id, reaction_type)
        
        # 업데이트된 반응 수 가져오기
        reaction_counts = PostReaction.get_reaction_counts(post_id)
        user_reaction = PostReaction.get_user_reaction(post_id, current_user.id)
        
        return jsonify({
            'success': True,
            'action': action,
            'reaction_counts': reaction_counts,
            'user_reaction': user_reaction
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/profile/<username>')
def profile(username):
    user = User.get_by_username(username)
    if not user:
        abort(404)
    
    # 사용자의 게시글 목록 가져오기
    posts = user.get_posts()
    post_count = user.get_post_count()
    
    return render_template('profile.html', 
                         profile_user=user,
                         posts=posts,
                         post_count=post_count)

@app.route('/profile/<username>/edit', methods=['GET', 'POST'])
@login_required
def edit_profile(username):
    user = User.get_by_username(username)
    if not user:
        abort(404)
    
    # 본인만 프로필 수정 가능
    if current_user.id != user.id:
        flash('자신의 프로필만 수정할 수 있습니다.')
        return redirect(url_for('profile', username=username))
    
    if request.method == 'POST':
        bio = request.form.get('bio', '').strip()
        
        if user.update_profile(bio):
            flash('프로필이 성공적으로 업데이트되었습니다.')
            return redirect(url_for('profile', username=username))
        else:
            flash('프로필 업데이트 중 오류가 발생했습니다.')
    
    return render_template('edit_profile.html', profile_user=user)

if __name__ == '__main__':
    app.run(debug=True)

