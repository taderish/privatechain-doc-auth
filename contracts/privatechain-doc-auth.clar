;; PrivateChain Library - Distributed Document Authentication System
;; A comprehensive system for securely storing, managing, and sharing authenticated documents
;; Built with privacy and security as core principles

;; Error Response Definitions
(define-constant ERROR_NOT_AUTHORIZED (err u200))
(define-constant ERROR_DOCUMENT_EXISTS (err u201))
(define-constant ERROR_DOCUMENT_NOT_FOUND (err u202))
(define-constant ERROR_INVALID_DOCUMENT_DATA (err u203))
(define-constant ERROR_INVALID_DESCRIPTOR (err u204))
(define-constant ERROR_INVALID_ACCESS_TYPE (err u205))
(define-constant ERROR_TIMESTAMP_INVALID (err u206))
(define-constant ERROR_ACCESS_DENIED (err u207))
(define-constant ERROR_INVALID_CLASSIFICATION (err u208))
(define-constant PLATFORM_ADMINISTRATOR tx-sender)

;; Access Permission Types
(define-constant PERMISSION_VIEW "view")
(define-constant PERMISSION_EDIT "edit")
(define-constant PERMISSION_FULL "full")

;; System Tracking Variables
(define-data-var document-counter uint u0)

;; Primary Storage Structures
(define-map document-repository
    { document-identifier: uint }
    {
        document-name: (string-ascii 50),
        creator: principal,
        verification-digest: (string-ascii 64),
        descriptor: (string-ascii 200),
        timestamp-created: uint,
        timestamp-updated: uint,
        classification: (string-ascii 20),
        tags: (list 5 (string-ascii 30))
    }
)

(define-map document-access-permissions
    { document-identifier: uint, authorized-user: principal }
    {
        permission-type: (string-ascii 10),
        timestamp-granted: uint,
        timestamp-expiration: uint,
        modification-allowed: bool
    }
)

;; ===============================
;; Verification Helper Functions
;; ===============================

;; Verifies document name meets system requirements
(define-private (verify-document-name (name (string-ascii 50)))
    (and
        (> (len name) u0)
        (<= (len name) u50)
    )
)

;; Ensures verification digest is properly formatted
(define-private (verify-digest-format (digest (string-ascii 64)))
    (and
        (is-eq (len digest) u64)
        (> (len digest) u0)
    )
)

;; Validates that all document tags meet format requirements
(define-private (verify-tag-collection (tag-collection (list 5 (string-ascii 30))))
    (and
        (>= (len tag-collection) u1)
        (<= (len tag-collection) u5)
        (is-eq (len (filter verify-individual-tag tag-collection)) (len tag-collection))
    )
)

;; Ensures each tag is properly formatted
(define-private (verify-individual-tag (tag (string-ascii 30)))
    (and
        (> (len tag) u0)
        (<= (len tag) u30)
    )
)

;; Validates that document descriptor meets format requirements
(define-private (verify-descriptor (descriptor (string-ascii 200)))
    (and
        (>= (len descriptor) u1)
        (<= (len descriptor) u200)
    )
)

;; Ensures document classification is valid
(define-private (verify-classification (classification (string-ascii 20)))
    (and
        (>= (len classification) u1)
        (<= (len classification) u20)
    )
)

;; Checks that permission type is one of the allowed values
(define-private (verify-permission-type (permission-type (string-ascii 10)))
    (or
        (is-eq permission-type PERMISSION_VIEW)
        (is-eq permission-type PERMISSION_EDIT)
        (is-eq permission-type PERMISSION_FULL)
    )
)

;; Validates that time period is reasonable
(define-private (verify-time-period (period uint))
    (and
        (> period u0)
        (<= period u52560) ;; Maximum period of approximately one year in blocks
    )
)

;; Ensures user is distinct from current executor
(define-private (verify-distinct-user (user principal))
    (not (is-eq user tx-sender))
)

;; Checks if sender is the document owner
(define-private (is-document-owner (document-identifier uint) (user principal))
    (match (map-get? document-repository { document-identifier: document-identifier })
        document-record (is-eq (get creator document-record) user)
        false
    )
)

;; Confirms document exists in repository
(define-private (document-exists (document-identifier uint))
    (is-some (map-get? document-repository { document-identifier: document-identifier }))
)

;; Validates that modification flag is properly set
(define-private (verify-modification-allowed (modification-allowed bool))
    (or (is-eq modification-allowed true) (is-eq modification-allowed false))
)

;; ===============================
;; Document Management Functions
;; ===============================

;; Creates a new document in the repository
(define-public (register-document 
    (document-name (string-ascii 50))
    (verification-digest (string-ascii 64))
    (descriptor (string-ascii 200))
    (classification (string-ascii 20))
    (tags (list 5 (string-ascii 30)))
)
    (let
        (
            (new-document-id (+ (var-get document-counter) u1))
            (current-block-height block-height)
        )
        ;; Input validation checks
        (asserts! (verify-document-name document-name) ERROR_INVALID_DOCUMENT_DATA)
        (asserts! (verify-digest-format verification-digest) ERROR_INVALID_DOCUMENT_DATA)
        (asserts! (verify-descriptor descriptor) ERROR_INVALID_DESCRIPTOR)
        (asserts! (verify-classification classification) ERROR_INVALID_CLASSIFICATION)
        (asserts! (verify-tag-collection tags) ERROR_INVALID_DESCRIPTOR)

        ;; Store document in repository
        (map-set document-repository
            { document-identifier: new-document-id }
            {
                document-name: document-name,
                creator: tx-sender,
                verification-digest: verification-digest,
                descriptor: descriptor,
                timestamp-created: current-block-height,
                timestamp-updated: current-block-height,
                classification: classification,
                tags: tags
            }
        )

        ;; Update system counter
        (var-set document-counter new-document-id)
        (ok new-document-id)
    )
)

;; Modifies an existing document's information
(define-public (modify-document
    (document-identifier uint)
    (new-document-name (string-ascii 50))
    (new-verification-digest (string-ascii 64))
    (new-descriptor (string-ascii 200))
    (new-tags (list 5 (string-ascii 30)))
)
    (let
        (
            (document-record (unwrap! (map-get? document-repository { document-identifier: document-identifier }) ERROR_DOCUMENT_NOT_FOUND))
        )
        ;; Authorization check
        (asserts! (is-document-owner document-identifier tx-sender) ERROR_NOT_AUTHORIZED)

        ;; Input validation checks
        (asserts! (verify-document-name new-document-name) ERROR_INVALID_DOCUMENT_DATA)
        (asserts! (verify-digest-format new-verification-digest) ERROR_INVALID_DOCUMENT_DATA)
        (asserts! (verify-descriptor new-descriptor) ERROR_INVALID_DESCRIPTOR)
        (asserts! (verify-tag-collection new-tags) ERROR_INVALID_DESCRIPTOR)

        ;; Update document record
        (map-set document-repository
            { document-identifier: document-identifier }
            (merge document-record {
                document-name: new-document-name,
                verification-digest: new-verification-digest,
                descriptor: new-descriptor,
                timestamp-updated: block-height,
                tags: new-tags
            })
        )
        (ok true)
    )
)

;; Grant access to document for another user
(define-public (authorize-access
    (document-identifier uint)
    (authorized-user principal)
    (permission-type (string-ascii 10))
    (access-duration uint)
    (modification-allowed bool)
)
    (let
        (
            (current-block-height block-height)
            (expiration-block-height (+ current-block-height access-duration))
        )
        ;; Validate document exists and sender is owner
        (asserts! (document-exists document-identifier) ERROR_DOCUMENT_NOT_FOUND)
        (asserts! (is-document-owner document-identifier tx-sender) ERROR_NOT_AUTHORIZED)

        ;; Input validation checks
        (asserts! (verify-distinct-user authorized-user) ERROR_INVALID_DOCUMENT_DATA)
        (asserts! (verify-permission-type permission-type) ERROR_INVALID_ACCESS_TYPE)
        (asserts! (verify-time-period access-duration) ERROR_TIMESTAMP_INVALID)
        (asserts! (verify-modification-allowed modification-allowed) ERROR_INVALID_DOCUMENT_DATA)

        ;; Set access permissions
        (map-set document-access-permissions
            { document-identifier: document-identifier, authorized-user: authorized-user }
            {
                permission-type: permission-type,
                timestamp-granted: current-block-height,
                timestamp-expiration: expiration-block-height,
                modification-allowed: modification-allowed
            }
        )
        (ok true)
    )
)

;; ===============================
;; Alternate Implementation Functions
;; ===============================

;; Enhanced clarity version of document modification
(define-public (enhanced-document-modification
    (document-identifier uint)
    (new-document-name (string-ascii 50))
    (new-verification-digest (string-ascii 64))
    (new-descriptor (string-ascii 200))
    (new-tags (list 5 (string-ascii 30)))
)
    (let
        (
            (document-record (unwrap! (map-get? document-repository { document-identifier: document-identifier }) ERROR_DOCUMENT_NOT_FOUND))
        )
        ;; Authorization check
        (asserts! (is-document-owner document-identifier tx-sender) ERROR_NOT_AUTHORIZED)

        ;; Create updated document record using merge operation
        (let
            (
                (updated-document (merge document-record {
                    document-name: new-document-name,
                    verification-digest: new-verification-digest,
                    descriptor: new-descriptor,
                    tags: new-tags,
                    timestamp-updated: block-height
                }))
            )
            ;; Store updated document
            (map-set document-repository { document-identifier: document-identifier } updated-document)
            (ok true)
        )
    )
)

;; Security-focused document modification function
(define-public (secure-document-update
    (document-identifier uint)
    (new-document-name (string-ascii 50))
    (new-verification-digest (string-ascii 64))
    (new-descriptor (string-ascii 200))
    (new-tags (list 5 (string-ascii 30)))
)
    (let
        (
            (document-record (unwrap! (map-get? document-repository { document-identifier: document-identifier }) ERROR_DOCUMENT_NOT_FOUND))
        )
        ;; Multi-stage validation for enhanced security
        (asserts! (is-document-owner document-identifier tx-sender) ERROR_NOT_AUTHORIZED)
        (asserts! (verify-document-name new-document-name) ERROR_INVALID_DOCUMENT_DATA)
        (asserts! (verify-digest-format new-verification-digest) ERROR_INVALID_DOCUMENT_DATA)
        (asserts! (verify-descriptor new-descriptor) ERROR_INVALID_DESCRIPTOR)
        (asserts! (verify-tag-collection new-tags) ERROR_INVALID_DESCRIPTOR)

        ;; Update document with proper audit trail
        (map-set document-repository
            { document-identifier: document-identifier }
            (merge document-record {
                document-name: new-document-name,
                verification-digest: new-verification-digest,
                descriptor: new-descriptor,
                timestamp-updated: block-height,
                tags: new-tags
            })
        )
        (ok true)
    )
)

;; Alternative storage structure for optimized lookups
(define-map optimized-document-storage
    { document-identifier: uint }
    {
        document-name: (string-ascii 50),
        creator: principal,
        verification-digest: (string-ascii 64),
        descriptor: (string-ascii 200),
        timestamp-created: uint,
        timestamp-updated: uint,
        classification: (string-ascii 20),
        tags: (list 5 (string-ascii 30))
    }
)

;; Optimized document registration using alternative storage
(define-public (advanced-document-registration
    (document-name (string-ascii 50))
    (verification-digest (string-ascii 64))
    (descriptor (string-ascii 200))
    (classification (string-ascii 20))
    (tags (list 5 (string-ascii 30)))
)
    (let
        (
            (new-document-id (+ (var-get document-counter) u1))
            (current-block-height block-height)
        )
        ;; Comprehensive validation suite
        (asserts! (verify-document-name document-name) ERROR_INVALID_DOCUMENT_DATA)
        (asserts! (verify-digest-format verification-digest) ERROR_INVALID_DOCUMENT_DATA)
        (asserts! (verify-descriptor descriptor) ERROR_INVALID_DESCRIPTOR)
        (asserts! (verify-classification classification) ERROR_INVALID_CLASSIFICATION)
        (asserts! (verify-tag-collection tags) ERROR_INVALID_DESCRIPTOR)

        ;; Use alternative optimized storage structure
        (map-set optimized-document-storage
            { document-identifier: new-document-id }
            {
                document-name: document-name,
                creator: tx-sender,
                verification-digest: verification-digest,
                descriptor: descriptor,
                timestamp-created: current-block-height,
                timestamp-updated: current-block-height,
                classification: classification,
                tags: tags
            }
        )

        ;; Update global document counter
        (var-set document-counter new-document-id)
        (ok new-document-id)
    )
)

;; Additional utility function for document verification
(define-private (validate-document-integrity 
    (document-id uint) 
    (expected-digest (string-ascii 64))
)
    (match (map-get? document-repository { document-identifier: document-id })
        doc-record (is-eq (get verification-digest doc-record) expected-digest)
        false
    )
)

